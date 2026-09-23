"""The detector - the object that is trained, saved, served and attacked.

Architecture
------------
::

    message
       |
       +-- D-NORM canonicalization ---+
       |                              |
       v                              v
    members (independent views)    obfuscation evidence
       | rules                        |
       | engineered (email+url+beh)   |
       | charngram                    |
       | wordtfidf                    |
       | transformer (optional)       |
       v                              |
    logistic fusion  <----------------+
       |
       v
    isotonic calibration
       |
       v
    D-VELOCITY guard  -->  banding (ALLOW / REVIEW / BLOCK)
       |
       v
    Verdict + evidence

Training discipline
-------------------
Three disjoint pools, because stacking on in-sample member scores is the
classic way to produce a fusion that looks excellent and generalises badly:

``fit``    members are fitted here (optionally with adversarial augmentation)
``stack``  members are *scored* here and the fusion weights are fitted on those
           out-of-sample scores
``cal``    the calibrator is fitted here, on fusion outputs it did not shape

The evaluation split is never touched by any of the three.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from sklearn.linear_model import LogisticRegression

from phishguard.config import Settings, get_settings
from phishguard.defenses.controls import DefenseConfig, apply_velocity_guard
from phishguard.features.assembler import FeatureAssembler
from phishguard.features.behavioral import behavioral_features
from phishguard.models.baseline import RuleBaseline
from phishguard.models.calibration import Calibrator
from phishguard.models.members import (
    EngineeredMember,
    TextMember,
    TransformerMember,
    char_ngram_member,
    word_tfidf_member,
)
from phishguard.schemas import (
    BAND_ALLOW,
    BAND_BLOCK,
    BAND_REVIEW,
    EmailMessage,
    Verdict,
)

MEMBER_BUILDERS = {
    "rules": lambda: RuleBaseline(),
    "engineered": lambda: EngineeredMember(),
    "charngram": lambda: char_ngram_member(),
    "wordtfidf": lambda: word_tfidf_member(),
    "transformer": lambda: TransformerMember(),
}


@dataclass(slots=True)
class TrainingReport:
    """What happened during training - goes straight into the model card."""

    members: list[str]
    n_fit: int
    n_stack: int
    n_cal: int
    n_adversarial_augmented: int
    fusion_weights: dict[str, float]
    fusion_intercept: float
    calibration: dict[str, Any]
    defenses: dict[str, bool]
    feature_contract: dict[str, Any]
    seconds: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "members": self.members,
            "n_fit": self.n_fit,
            "n_stack": self.n_stack,
            "n_cal": self.n_cal,
            "n_adversarial_augmented": self.n_adversarial_augmented,
            "fusion_weights": self.fusion_weights,
            "fusion_intercept": round(self.fusion_intercept, 6),
            "calibration": self.calibration,
            "defenses": self.defenses,
            "feature_contract": self.feature_contract,
            "training_seconds": round(self.seconds, 2),
        }


class PhishGuardDetector:
    """Trained detector: members + fusion + calibration + decision policy."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        member_names: tuple[str, ...] | None = None,
        defenses: DefenseConfig | None = None,
        families: tuple[str, ...] = ("email", "url", "behavioral"),
    ) -> None:
        self.settings = settings or get_settings()
        self.defenses = defenses or DefenseConfig()
        self.families = families
        names = member_names or self.settings.enabled_members
        if not self.defenses.ensemble:
            # Ablation arm D-ENSEMBLE=off: keep the single strongest view only.
            names = ("engineered",) if "engineered" in names else names[:1]
        self.member_names: tuple[str, ...] = tuple(names)

        self.members: dict[str, Any] = {}
        for name in self.member_names:
            builder = MEMBER_BUILDERS.get(name)
            if builder is None:
                raise ValueError(f"unknown member {name!r}")
            member = builder()
            if isinstance(member, EngineeredMember):
                member.assembler = FeatureAssembler(
                    families=families, canonicalize_urls=self.defenses.url_canon
                )
            if isinstance(member, TextMember):
                member.use_canonical = self.defenses.norm
            self.members[name] = member

        self.fusion: LogisticRegression | None = None
        self.calibrator = Calibrator(method="isotonic")
        self.model_version: str = "untrained"
        self.report: TrainingReport | None = None
        self.trained_at: str = ""

    # ------------------------------------------------------------- training
    def fit(
        self,
        messages: list[EmailMessage],
        y: np.ndarray | list[int],
        *,
        stack_fraction: float = 0.22,
        cal_fraction: float = 0.18,
        adversarial_augment: bool = True,
        seed: int | None = None,
    ) -> TrainingReport:
        """Fit members, fusion and calibrator on three disjoint pools."""
        start = time.perf_counter()
        y = np.asarray(y, dtype=np.int64)
        if len(messages) != len(y):
            raise ValueError("messages and labels must be the same length")
        seed = self.settings.random_seed if seed is None else seed
        rng = np.random.default_rng(seed)

        idx = rng.permutation(len(messages))
        n_cal = max(int(len(idx) * cal_fraction), 1)
        n_stack = max(int(len(idx) * stack_fraction), 1)
        cal_idx = idx[:n_cal]
        stack_idx = idx[n_cal : n_cal + n_stack]
        fit_idx = idx[n_cal + n_stack :]
        if len(fit_idx) < 50:
            raise ValueError(
                f"not enough training data: {len(fit_idx)} messages left for member "
                "fitting after reserving stacking and calibration pools"
            )

        fit_msgs = [messages[i] for i in fit_idx]
        fit_y = y[fit_idx]

        # --- D-ADVTRAIN -------------------------------------------------
        n_augmented = 0
        if adversarial_augment and self.defenses.adv_train:
            aug_msgs, aug_y = self._augment(fit_msgs, fit_y, seed=seed)
            n_augmented = len(aug_msgs) - len(fit_msgs)
            fit_msgs, fit_y = aug_msgs, aug_y

        for member in self.members.values():
            member.fit(fit_msgs, fit_y)

        # --- fusion on out-of-sample member scores -----------------------
        stack_msgs = [messages[i] for i in stack_idx]
        stack_y = y[stack_idx]
        Z_stack = self._member_matrix(stack_msgs)
        self.fusion = LogisticRegression(
            max_iter=2000, C=2.0, solver="lbfgs", class_weight="balanced"
        )
        self.fusion.fit(Z_stack, stack_y)

        # --- calibration on a third, untouched pool ----------------------
        cal_msgs = [messages[i] for i in cal_idx]
        cal_y = y[cal_idx]
        raw_cal = self._fusion_raw(self._member_matrix(cal_msgs))
        self.calibrator.fit(raw_cal, cal_y)
        cal_report = self.calibrator.report(raw_cal, cal_y)
        cal_report.pop("reliability", None)  # kept out of the model card summary

        self.trained_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.model_version = self._make_version(len(messages), seed)
        self.report = TrainingReport(
            members=list(self.member_names),
            n_fit=len(fit_idx),
            n_stack=len(stack_idx),
            n_cal=len(cal_idx),
            n_adversarial_augmented=n_augmented,
            fusion_weights={
                name: round(float(w), 5)
                for name, w in zip(self.member_names, self.fusion.coef_[0], strict=True)
            },
            fusion_intercept=float(self.fusion.intercept_[0]),
            calibration=cal_report,
            defenses=self.defenses.as_dict(),
            feature_contract=self._engineered_contract(),
            seconds=time.perf_counter() - start,
        )
        return self.report

    def _augment(
        self, messages: list[EmailMessage], y: np.ndarray, *, seed: int
    ) -> tuple[list[EmailMessage], np.ndarray]:
        """Defensive control ``D-ADVTRAIN``.

        Adversarial variants are generated for phishing examples only. Applying
        the same perturbations to legitimate mail would teach the model that
        obfuscation is label-neutral, which is the opposite of what the
        obfuscation features are for.
        """
        from phishguard.adversarial.transforms import random_perturbation

        rng = np.random.default_rng(seed + 1)
        extra_msgs: list[EmailMessage] = []
        extra_y: list[int] = []
        multiplier = max(int(self.settings.adv_train_multiplier), 0)
        phish_positions = np.flatnonzero(y == 1)
        for pos in phish_positions:
            for _ in range(multiplier):
                extra_msgs.append(random_perturbation(messages[int(pos)], rng))
                extra_y.append(1)
        if not extra_msgs:
            return messages, y
        return messages + extra_msgs, np.concatenate([y, np.asarray(extra_y, dtype=np.int64)])

    def _make_version(self, n: int, seed: int) -> str:
        import hashlib

        payload = "|".join(
            [
                "|".join(self.member_names),
                "|".join(sorted(self.defenses.active_ids)),
                "|".join(self.families),
                str(n), str(seed), self.trained_at,
            ]
        )
        return f"pg-{hashlib.sha256(payload.encode()).hexdigest()[:10]}"

    def _engineered_contract(self) -> dict[str, Any]:
        eng = self.members.get("engineered")
        if isinstance(eng, EngineeredMember):
            return eng.assembler.contract()
        return {"families": list(self.families), "n_features": 0, "names": []}

    # ------------------------------------------------------------ inference
    def _member_matrix(self, messages: list[EmailMessage]) -> np.ndarray:
        cols = [self.members[name].score(messages) for name in self.member_names]
        return np.column_stack(cols) if cols else np.zeros((len(messages), 0))

    def _fusion_raw(self, Z: np.ndarray) -> np.ndarray:
        if self.fusion is None:
            raise RuntimeError("detector is not trained")
        return self.fusion.predict_proba(Z)[:, 1]

    def predict_proba(self, messages: list[EmailMessage]) -> np.ndarray:
        """Calibrated P(phishing) for a batch, before the velocity guard."""
        if not messages:
            return np.zeros(0, dtype=np.float64)
        return self.calibrator.transform(self._fusion_raw(self._member_matrix(messages)))

    def predict_proba_raw(self, messages: list[EmailMessage]) -> np.ndarray:
        """Uncalibrated fusion probability.

        This is the surface the adversarial evaluation attacks by default, and
        the reason is a measurement problem worth stating plainly.

        Isotonic calibration fitted on a well-separated calibration set becomes
        close to a step function: almost every phishing message maps to exactly
        1.0, and a perturbation that genuinely moves the underlying fusion score
        from 0.995 to 0.93 still maps to 1.0. Attacking the calibrated output
        therefore reports an attack success rate of zero - not because the model
        is robust, but because the attacker is being handed a signal with no
        gradient in it.

        Reporting that as robustness would be self-deception. The adversarial
        suite instead attacks the raw fusion score, which is the *conservative*
        choice: it grants the attacker a finer-grained oracle than the deployed
        API exposes, so the measured attack success rate is an upper bound on
        what a real attacker achieves against the deployed system. Both numbers
        appear in the evaluation dossier.
        """
        if not messages:
            return np.zeros(0, dtype=np.float64)
        return self._fusion_raw(self._member_matrix(messages))

    def predict(self, messages: list[EmailMessage], threshold: float | None = None) -> np.ndarray:
        thr = self.settings.block_threshold if threshold is None else threshold
        return (self.predict_proba(messages) >= thr).astype(np.int64)

    def band_of(self, score: float) -> str:
        """Map a probability onto the operational decision band."""
        if not self.defenses.abstain:
            return BAND_BLOCK if score >= self.settings.block_threshold else BAND_ALLOW
        if score >= self.settings.block_threshold:
            return BAND_BLOCK
        if score >= self.settings.review_threshold:
            return BAND_REVIEW
        return BAND_ALLOW

    def assess(self, message: EmailMessage, *, explain: bool = True) -> Verdict:
        """Full single-message assessment with evidence. This is what the API serves."""
        started = time.perf_counter()
        Z = self._member_matrix([message])
        raw = float(self._fusion_raw(Z)[0])
        score = float(self.calibrator.transform(np.array([raw]))[0])

        beh = behavioral_features(message, message.behavioral)
        score, velocity_note = apply_velocity_guard(
            score, beh, enabled=self.defenses.velocity
        )

        member_scores = {
            name: float(Z[0, j]) for j, name in enumerate(self.member_names)
        }
        band = self.band_of(score)

        evidence: list[dict[str, Any]] = []
        if explain:
            from phishguard.explain.evidence import build_evidence

            evidence = build_evidence(self, message, score, member_scores)
        if velocity_note:
            evidence.append(
                {
                    "kind": "defense",
                    "id": "D-VELOCITY",
                    "title": "Campaign burst guard applied",
                    "detail": velocity_note,
                    "direction": "phishing",
                    "weight": 0.1,
                }
            )

        return Verdict(
            score=score,
            band=band,
            label=int(score >= self.settings.block_threshold),
            model_version=self.model_version,
            evidence=evidence,
            signals={
                "raw_fusion": round(raw, 6),
                "trust_deficit": round(beh.get("beh_trust_deficit", 0.0), 4),
                "review_threshold": self.settings.review_threshold,
                "block_threshold": self.settings.block_threshold,
            },
            member_scores=member_scores,
            defenses_applied=self.defenses.active_ids,
            latency_ms=(time.perf_counter() - started) * 1000.0,
            behavioral_available=bool(message.behavioral.available),
            abstained=band == BAND_REVIEW,
        )

    # --------------------------------------------------------------- misc
    @property
    def is_trained(self) -> bool:
        return self.fusion is not None

    def describe(self) -> dict[str, Any]:
        """Model metadata for ``GET /api/v1/model`` and the model card."""
        return {
            "model_version": self.model_version,
            "trained_at": self.trained_at,
            "members": list(self.member_names),
            "feature_families": list(self.families),
            "defenses": self.defenses.as_dict(),
            "active_defense_ids": self.defenses.active_ids,
            "thresholds": {
                "review": self.settings.review_threshold,
                "block": self.settings.block_threshold,
            },
            "calibration_method": self.calibrator.fitted_method,
            "training": self.report.as_dict() if self.report else None,
        }

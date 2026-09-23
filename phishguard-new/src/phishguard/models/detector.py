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

The pools are drawn **by campaign**, like the train/test split: a campaign's
near-identical siblings never sit on both sides of a pool boundary, so the
stacking and calibration pools see campaigns the members never saw -- which
is what deployment looks like. The evaluation split is never touched by any
of the three.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
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


@dataclass(slots=True)
class _Decision:
    """Everything the decision policy concluded about one message."""

    raw: float
    score: float
    band: str
    spread: float
    abstained_by_disagreement: bool
    velocity_note: str | None
    behavioral: dict[str, float]
    member_scores: dict[str, float]


def _campaign_pools(
    messages: list[EmailMessage], n_cal: int, n_stack: int, rng: np.random.Generator
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Calibration, stacking and fitting pools that never split a campaign.

    Campaigns are visited in random order and assigned whole to the
    calibration pool until it holds ``n_cal`` messages, then to the stacking
    pool, then to member fitting. A message with no ``group_key`` is its own
    campaign. Row order inside each pool is shuffled.
    """
    keys = [m.group_key or f"row:{i}" for i, m in enumerate(messages)]
    by_key: dict[str, list[int]] = {}
    for i, k in enumerate(keys):
        by_key.setdefault(k, []).append(i)
    names = list(by_key)
    order = [names[j] for j in rng.permutation(len(names))]
    cal: list[int] = []
    stack: list[int] = []
    fit: list[int] = []
    for k in order:
        if len(cal) < n_cal:
            cal.extend(by_key[k])
        elif len(stack) < n_stack:
            stack.extend(by_key[k])
        else:
            fit.extend(by_key[k])
    return (
        rng.permutation(np.asarray(cal, dtype=np.int64)),
        rng.permutation(np.asarray(stack, dtype=np.int64)),
        rng.permutation(np.asarray(fit, dtype=np.int64)),
    )


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

        # Band thresholds actually in force. They start at the configured
        # constants and are replaced during ``fit`` by thresholds that achieve
        # the deployment's false-alarm budget on the held-out calibration pool
        # (see ``Settings.tune_thresholds``). Keeping them as instance state
        # rather than reading ``settings`` at decision time is what lets a
        # saved model carry its own operating point: two models trained on
        # different data have different score distributions and must not share
        # a hard-coded boundary.
        self.review_threshold: float = self.settings.review_threshold
        self.block_threshold: float = self.settings.block_threshold
        self.threshold_source: str = "configured"
        #: Legitimate-mail reference for drift monitoring, captured by ``fit``.
        self.drift_reference: Any = None

    def __setstate__(self, state: dict[str, Any]) -> None:
        """Load a model saved before per-model thresholds existed.

        Detectors are persisted with joblib, so a model trained by an earlier
        version unpickles without ``review_threshold``, ``block_threshold`` or
        ``threshold_source`` in its instance dict -- and every decision path
        reads those attributes, so the first scan after an upgrade would raise
        ``AttributeError`` on a model the registry reports as healthy. Backfill
        them from settings, which is exactly the policy that model was trained
        and evaluated under.
        """
        self.__dict__.update(state)
        settings = state.get("settings") or get_settings()
        if "review_threshold" not in state:
            self.review_threshold = settings.review_threshold
        if "block_threshold" not in state:
            self.block_threshold = settings.block_threshold
        if "threshold_source" not in state:
            self.threshold_source = "configured (model predates threshold fitting)"
        if "drift_reference" not in state:
            # Models saved before drift monitoring load without a reference;
            # the monitor then says so and asks for a retrain, rather than
            # comparing against nothing.
            self.drift_reference = None

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
        grouped_pools: bool = True,
    ) -> TrainingReport:
        """Fit members, fusion and calibrator on three disjoint pools.

        The pools are drawn **by campaign** (``group_key``), not by row. The
        train/test split already keeps campaigns whole to stop near-identical
        siblings inflating the test score; the same leak exists *inside*
        training. With row-level pools, most calibration messages have a
        sibling in the member-fitting pool, so the members score them with a
        confidence they will not have on a new campaign: the calibration pool
        looks perfectly separated, the false-alarm budget cannot be estimated
        from it, and the calibrator learns an optimism that does not transfer.
        Drawing whole campaigns makes the stacking and calibration pools look
        like what the model will actually meet -- mail from campaigns it has
        never seen -- and gives the drift monitor a reference made of whole
        campaigns, which is how live traffic arrives.
        """
        start = time.perf_counter()
        y = np.asarray(y, dtype=np.int64)
        if len(messages) != len(y):
            raise ValueError("messages and labels must be the same length")
        seed = self.settings.random_seed if seed is None else seed
        rng = np.random.default_rng(seed)

        n_cal = max(int(len(messages) * cal_fraction), 1)
        n_stack = max(int(len(messages) * stack_fraction), 1)
        if grouped_pools:
            cal_idx, stack_idx, fit_idx = _campaign_pools(messages, n_cal, n_stack, rng)
        else:
            idx = rng.permutation(len(messages))
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

        # --- operating point, fitted to the false-alarm budget -------------
        # The calibration pool is untouched by fitting and stacking, so it is
        # the right place to measure a false-positive rate. Both thresholds
        # come from the same pool and the same comparison (>=) used at
        # decision time, so the budget the operator asked for is the budget
        # they get.
        self._fit_thresholds(self.calibrator.transform(raw_cal), cal_y)

        # --- drift reference -----------------------------------------------
        # What legitimate mail looked like to this model, measured on the same
        # untouched pool. Stored with the model so that a monitor comparing
        # live traffic always compares against *this* model's view of normal.
        try:
            from phishguard.monitoring.drift import build_reference

            # Stacking and calibration pools together: both hold whole
            # campaigns (see _campaign_pools) and neither was seen by the
            # members, so their member scores are what new mail will get. The
            # monitor's null resamples campaigns, so more campaigns in the
            # reference means better-calibrated alarms.
            ref_idx = np.concatenate([cal_idx, stack_idx])
            self.drift_reference = build_reference(self, [messages[i] for i in ref_idx], y[ref_idx])
        except Exception:  # noqa: BLE001 - monitoring must never fail a training run
            self.drift_reference = None

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

    def _fit_thresholds(self, cal_scores: np.ndarray, cal_y: np.ndarray) -> None:
        """Choose the two band boundaries from a false-alarm budget.

        A deployment states its tolerance the way a mail team actually states
        it -- "no more than four legitimate messages in a thousand may be
        auto-quarantined" -- and the thresholds follow from that, per model.

        The search walks the achieved false-positive rate over the distinct
        negative scores rather than taking a quantile, for the reason set out
        in :func:`phishguard.eval.metrics.threshold_for_target_fpr`: a
        well-separated calibrated model piles most negatives onto an exact
        mass point, and a quantile of a mass point classifies the whole corpus
        as phishing.

        If the pool has no negatives, or the fitted thresholds would invert,
        the configured constants are kept and ``threshold_source`` records
        that -- a degenerate pool must not silently produce a boundary of 0.
        """
        if not self.settings.tune_thresholds:
            self.threshold_source = "configured"
            return

        scores = np.asarray(cal_scores, dtype=np.float64)
        y = np.asarray(cal_y).astype(int)
        negatives = scores[y == 0]
        if negatives.size < 30:
            self.threshold_source = "configured (calibration pool too small)"
            return

        def at_budget(target: float) -> float:
            allowed = int(np.floor(max(target, 0.0) * negatives.size))
            if allowed <= 0:
                return float(np.nextafter(negatives.max(), np.inf))
            # Smallest candidate whose achieved FPR stays within the budget.
            for candidate in np.unique(negatives):
                if int((negatives >= candidate).sum()) <= allowed:
                    return float(candidate)
            return float(np.nextafter(negatives.max(), np.inf))

        review = at_budget(self.settings.target_review_fpr)
        block = at_budget(self.settings.target_block_fpr)

        # Clamp into (0, 1] and keep the bands ordered. A review boundary of
        # exactly 0 would mark every message for human attention.
        # A perfectly separated calibration pool carries no information about
        # where a false-alarm budget sits: if every legitimate message scores
        # exactly 0.0, no threshold above zero has a measurable false-positive
        # rate, and the search degenerates to "block everything above zero".
        # That is not a tuned operating point, it is an artefact of isotonic
        # saturation, so the configured policy constants are kept instead and
        # the reason is recorded rather than hidden.
        floor = 1e-4
        if review < floor or block < floor:
            self.threshold_source = (
                "configured (calibration pool perfectly separated, so a "
                "false-alarm budget is not estimable from it)"
            )
            return

        review = min(max(review, floor), 1.0)
        block = min(max(block, review), 1.0)

        # Two sanity constraints the fitted pair must satisfy to be usable as
        # a policy, both of which a small calibration pool routinely violates:
        #
        # 1. A block threshold below 0.5 auto-quarantines mail the model
        #    itself judges more likely legitimate than not. No false-alarm
        #    budget justifies that; it means the budget was unreachable.
        # 2. The bands must be far enough apart to *be* bands. On a small pool
        #    the two budgets collapse onto neighbouring scores -- 0.065 and
        #    0.075 was observed -- which leaves a one-percent abstention band
        #    and makes the middle band decorative.
        #
        # Failing either, the configured policy constants are kept and the
        # reason is recorded, rather than shipping a boundary that is an
        # artefact of pool size.
        if block < 0.5:
            self.threshold_source = (
                "configured (the requested false-alarm budget would put the "
                "block boundary below 0.5, which cannot be justified)"
            )
            return
        if block - review < 0.10:
            self.threshold_source = (
                "configured (fitted bands were too close together to form a "
                "usable abstention band; calibration pool is likely too small)"
            )
            return

        self.review_threshold = round(review, 6)
        self.block_threshold = round(block, 6)
        self.threshold_source = (
            f"fitted on the calibration pool to "
            f"review<={self.settings.target_review_fpr:.3f} FPR, "
            f"block<={self.settings.target_block_fpr:.3f} FPR"
        )

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
                str(n),
                str(seed),
                self.trained_at,
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
        from phishguard.features.cache import batch_cache
        from phishguard.service.tracing import span

        # One memo per call: the rule checklist and the engineered member share
        # email-feature and link extraction instead of each repeating it.
        cols = []
        with batch_cache():
            for name in self.member_names:
                with span(f"member.{name}"):
                    cols.append(self.members[name].score(messages))
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
        thr = self.block_threshold if threshold is None else threshold
        return (self.predict_proba(messages) >= thr).astype(np.int64)

    def band_of(self, score: float) -> str:
        """Map a probability onto the operational decision band."""
        if not self.defenses.abstain:
            return BAND_BLOCK if score >= self.block_threshold else BAND_ALLOW
        if score >= self.block_threshold:
            return BAND_BLOCK
        if score >= self.review_threshold:
            return BAND_REVIEW
        return BAND_ALLOW

    # ------------------------------------------------------------- abstention
    def disagreement(self, member_scores: dict[str, float]) -> float:
        """Spread between the most and least alarmed ensemble member.

        This is the uncertainty signal the abstention control acts on. It is
        deliberately the raw spread rather than a variance: what matters
        operationally is that *some* view of the message is confident and
        another confident view contradicts it, which a variance over four
        members would dilute.
        """
        if len(member_scores) < self.settings.abstain_min_members:
            return 0.0
        values = [float(v) for v in member_scores.values()]
        return float(max(values) - min(values))

    def band_with_abstention(
        self, score: float, member_scores: dict[str, float]
    ) -> tuple[str, float, bool]:
        """Decision band, withholding a confident verdict when members disagree.

        Returns ``(band, disagreement, abstained_by_disagreement)``. The score
        itself is never altered -- the audit log keeps the number the model
        produced, and only the *action* changes. That separation matters: an
        analyst reviewing the queue needs to see that the system scored 0.03
        and still escalated, not a score quietly rewritten to 0.5.
        """
        band = self.band_of(score)
        if not self.defenses.abstain:
            return band, 0.0, False
        spread = self.disagreement(member_scores)
        if spread >= self.settings.abstain_disagreement and band != BAND_REVIEW:
            # Escalate-only mode never downgrades a block: disagreement may make
            # the decision more cautious, never less.
            if (
                getattr(self.settings, "abstain_mode", "symmetric") == "escalate"
                and band == BAND_BLOCK
            ):
                return band, spread, False
            return BAND_REVIEW, spread, True
        return band, spread, False

    def bands(self, messages: list[EmailMessage]) -> list[str]:
        """Deployed decision bands for a batch -- every control included.

        Evaluation code must use this rather than banding ``predict_proba``
        output directly, because thresholding the score alone measures a
        system that is not the one being shipped. It goes through the same
        :meth:`_decisions` as the served path, so the velocity guard and
        abstention are applied exactly as the API applies them. (An earlier
        version applied abstention here but not the velocity guard, so every
        evaluation measured a detector without D-VELOCITY.)
        """
        return [d.band for d in self._decisions(messages)]

    def decided_scores(self, messages: list[EmailMessage]) -> np.ndarray:
        """Scores after every score-modifying control, as the API reports them."""
        return np.array([d.score for d in self._decisions(messages)], dtype=np.float64)

    def _decisions(
        self, messages: list[EmailMessage], Z: np.ndarray | None = None
    ) -> list[_Decision]:
        """The one decision function behind ``assess``, ``assess_batch`` and ``bands``.

        Scoring is vectorised across the batch (one member matrix, one fusion,
        one calibration); the per-message controls -- the velocity guard, then
        abstention on member disagreement -- run in the same order the single
        message path has always used.
        """
        if not messages:
            return []
        from phishguard.service.tracing import span

        Z = self._member_matrix(messages) if Z is None else Z
        with span("fusion"):
            raws = self._fusion_raw(Z)
            calibrated = self.calibrator.transform(raws)
        out: list[_Decision] = []
        for i, message in enumerate(messages):
            beh = behavioral_features(message, message.behavioral)
            score, velocity_note = apply_velocity_guard(
                float(calibrated[i]), beh, enabled=self.defenses.velocity
            )
            member_scores = {name: float(Z[i, j]) for j, name in enumerate(self.member_names)}
            band, spread, abstained = self.band_with_abstention(score, member_scores)
            out.append(
                _Decision(
                    raw=float(raws[i]),
                    score=score,
                    band=band,
                    spread=spread,
                    abstained_by_disagreement=abstained,
                    velocity_note=velocity_note,
                    behavioral=beh,
                    member_scores=member_scores,
                )
            )
        return out

    def assess(self, message: EmailMessage, *, explain: bool = True) -> Verdict:
        """Full single-message assessment with evidence. This is what the API serves."""
        from phishguard.features.cache import batch_cache

        started = time.perf_counter()
        # One memo across scoring *and* evidence generation: the explanation
        # re-reads the same email features and links the scoring just computed.
        with batch_cache():
            decision = self._decisions([message])[0]
            return self._verdict(
                message,
                decision,
                explain=explain,
                latency_ms=(time.perf_counter() - started) * 1000.0,
            )

    def assess_batch(
        self, messages: list[EmailMessage], *, explain: str = "queue"
    ) -> list[Verdict]:
        """Assess many messages in one vectorised pass.

        ``explain`` controls the expensive part -- evidence generation, which
        re-scores perturbed variants of each message and costs several times
        more than scoring it:

        ``"queue"``  explain only REVIEW and BLOCK, the messages an analyst
                     will actually open (the default: an ALLOW nobody looks at
                     does not need a justification written for it)
        ``"all"``    explain everything (identical to calling ``assess`` on each)
        ``"none"``   scores and bands only

        Scores, bands and member scores are identical to ``assess`` whatever
        ``explain`` is set to; only the evidence list differs.
        """
        if explain not in {"queue", "all", "none"}:
            raise ValueError("explain must be 'queue', 'all' or 'none'")
        from phishguard.features.cache import batch_cache

        started = time.perf_counter()
        verdicts: list[Verdict] = []
        with batch_cache():
            decisions = self._decisions(messages)
            per_message = ((time.perf_counter() - started) * 1000.0) / max(len(messages), 1)
            for message, decision in zip(messages, decisions, strict=True):
                want = explain == "all" or (explain == "queue" and decision.band != BAND_ALLOW)
                t0 = time.perf_counter()
                verdict = self._verdict(message, decision, explain=want, latency_ms=0.0)
                verdict.latency_ms = per_message + (time.perf_counter() - t0) * 1000.0
                verdicts.append(verdict)
        return verdicts

    def _verdict(
        self, message: EmailMessage, d: _Decision, *, explain: bool, latency_ms: float
    ) -> Verdict:
        evidence: list[dict[str, Any]] = []
        if explain:
            from phishguard.explain.evidence import build_evidence
            from phishguard.service.tracing import span

            # Evidence re-scores perturbed copies of the message; those member
            # calls are counted into this span rather than listed one by one.
            with span("explain", record_children=False):
                evidence = build_evidence(self, message, d.score, d.member_scores)
        if d.abstained_by_disagreement:
            ms = d.member_scores
            hi = max(ms, key=lambda k: ms[k])
            lo = min(ms, key=lambda k: ms[k])
            evidence.insert(
                0,
                {
                    "kind": "context",
                    "id": "D-ABSTAIN",
                    "title": "Escalated to human review: the readers disagree",
                    "detail": (
                        f"`{hi}` scored {ms[hi]:.2f} while `{lo}` scored "
                        f"{ms[lo]:.2f} — a spread of {d.spread:.2f}, above "
                        f"the {self.settings.abstain_disagreement:.2f} limit. Two "
                        "independent readings of this message contradict each "
                        "other, so the combined score is not a reliable basis "
                        "for an automatic decision."
                    ),
                    "direction": "neutral",
                    "weight": 0.0,
                },
            )
        if d.velocity_note:
            evidence.append(
                {
                    "kind": "defense",
                    "id": "D-VELOCITY",
                    "title": "Campaign burst guard applied",
                    "detail": d.velocity_note,
                    "direction": "phishing",
                    "weight": 0.1,
                }
            )
        return Verdict(
            score=d.score,
            band=d.band,
            label=int(d.score >= self.block_threshold),
            model_version=self.model_version,
            evidence=evidence,
            signals={
                "raw_fusion": round(d.raw, 6),
                "trust_deficit": round(d.behavioral.get("beh_trust_deficit", 0.0), 4),
                "review_threshold": self.review_threshold,
                "block_threshold": self.block_threshold,
                "member_disagreement": round(d.spread, 4),
            },
            member_scores=d.member_scores,
            defenses_applied=self.defenses.active_ids,
            latency_ms=latency_ms,
            behavioral_available=bool(message.behavioral.available),
            abstained=d.band == BAND_REVIEW,
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
                "review": self.review_threshold,
                "block": self.block_threshold,
                "source": self.threshold_source,
            },
            "calibration_method": self.calibrator.fitted_method,
            "training": self.report.as_dict() if self.report else None,
        }

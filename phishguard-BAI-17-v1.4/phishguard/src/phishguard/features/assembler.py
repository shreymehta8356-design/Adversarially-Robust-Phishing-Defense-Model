"""Feature assembler - joins the three families into one stable vector.

The assembler owns the *feature contract*: a fixed, ordered list of names that
does not change between training and serving. Any drift between the two is the
single most common cause of a model that scores well offline and fails in
production, so the order is derived once, frozen into the saved artefact, and
verified at load time.

It also owns modality gating (``families=("email","url")`` for the ablation
study) and the link-extraction step that connects the email body to the URL
family.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from phishguard.features.behavioral import BEHAVIORAL_FEATURE_NAMES, behavioral_features
from phishguard.features.cache import email_features_for, links_for
from phishguard.features.email import EMAIL_FEATURE_NAMES
from phishguard.features.urls import LINK_AGG_NAMES, aggregate_link_features
from phishguard.schemas import EmailMessage

FEATURE_FAMILIES: tuple[str, ...] = ("email", "url", "behavioral")

_FAMILY_NAMES: dict[str, tuple[str, ...]] = {
    "email": EMAIL_FEATURE_NAMES,
    "url": LINK_AGG_NAMES,
    "behavioral": BEHAVIORAL_FEATURE_NAMES,
}


@dataclass(slots=True)
class FeatureVector:
    """One message's features plus the provenance needed for explanations."""

    values: np.ndarray
    names: tuple[str, ...]
    links: list[tuple[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, float]:
        return {n: float(v) for n, v in zip(self.names, self.values, strict=True)}

    def top(self, k: int = 10) -> list[tuple[str, float]]:
        idx = np.argsort(-np.abs(self.values))[:k]
        return [(self.names[i], float(self.values[i])) for i in idx]


class FeatureAssembler:
    """Builds the engineered feature matrix.

    Parameters
    ----------
    families:
        Which feature families to include. Dropping one is exactly what the
        modality-ablation experiment does.
    canonicalize_urls:
        Defensive control ``D-URL``. Off = the extractor sees the URL exactly
        as written, which is what the "no defenses" ablation arm measures.
    """

    def __init__(
        self,
        families: tuple[str, ...] = FEATURE_FAMILIES,
        *,
        canonicalize_urls: bool = True,
    ) -> None:
        unknown = set(families) - set(FEATURE_FAMILIES)
        if unknown:
            raise ValueError(f"unknown feature families: {sorted(unknown)}")
        if not families:
            raise ValueError("at least one feature family is required")
        self.families = tuple(f for f in FEATURE_FAMILIES if f in families)
        self.canonicalize_urls = canonicalize_urls
        self.names: tuple[str, ...] = tuple(
            name for fam in self.families for name in _FAMILY_NAMES[fam]
        )
        self._index = {name: i for i, name in enumerate(self.names)}

    # ------------------------------------------------------------------ api
    @property
    def n_features(self) -> int:
        return len(self.names)

    def family_of(self, name: str) -> str:
        for fam, names in _FAMILY_NAMES.items():
            if name in names:
                return fam
        return "unknown"

    def extract(self, msg: EmailMessage) -> FeatureVector:
        """Full feature vector for one message."""
        merged: dict[str, float] = {}
        links: list[tuple[str, str]] = []

        email_sig: dict[str, float] = {}
        if "email" in self.families or "behavioral" in self.families:
            email_sig = email_features_for(msg)
        if "email" in self.families:
            merged.update(email_sig)

        if "url" in self.families:
            links = links_for(msg)
            merged.update(aggregate_link_features(links, canonicalize=self.canonicalize_urls))

        if "behavioral" in self.families:
            merged.update(behavioral_features(msg, msg.behavioral, email_signals=email_sig))

        values = np.fromiter(
            (float(merged.get(n, 0.0)) for n in self.names),
            dtype=np.float64,
            count=len(self.names),
        )
        np.nan_to_num(values, copy=False, nan=0.0, posinf=1e9, neginf=-1e9)
        return FeatureVector(values=values, names=self.names, links=links)

    def transform(self, messages: list[EmailMessage]) -> np.ndarray:
        """Feature matrix ``(n_messages, n_features)``."""
        if not messages:
            return np.zeros((0, self.n_features), dtype=np.float64)
        out = np.empty((len(messages), self.n_features), dtype=np.float64)
        for i, m in enumerate(messages):
            out[i] = self.extract(m).values
        return out

    # ---------------------------------------------------------------- misc
    def contract(self) -> dict[str, object]:
        """Serializable description of the feature contract."""
        return {
            "families": list(self.families),
            "canonicalize_urls": self.canonicalize_urls,
            "n_features": self.n_features,
            "names": list(self.names),
            "family_sizes": {f: len(_FAMILY_NAMES[f]) for f in self.families},
        }

    def verify(self, contract: dict[str, object]) -> None:
        """Fail loudly when a loaded model expects a different feature layout."""
        expected = list(contract.get("names", []))
        if expected and expected != list(self.names):
            missing = set(expected) - set(self.names)
            added = set(self.names) - set(expected)
            raise RuntimeError(
                "feature contract mismatch between saved model and runtime: "
                f"{len(missing)} missing, {len(added)} unexpected "
                f"(first missing: {sorted(missing)[:3]}, first added: {sorted(added)[:3]})"
            )

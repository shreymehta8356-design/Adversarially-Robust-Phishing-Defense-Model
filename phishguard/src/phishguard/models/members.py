"""Fusion members - the independent views the ensemble combines.

Each member reads the message through a different lens, which is the whole
point: an adversarial edit that lowers one view's score frequently raises
another's, and the fusion only breaks when an attacker can move all of them at
once.

============  ==========================================================
Member        View of the message
============  ==========================================================
``rules``     analyst checklist over named signals (no learning)
``engineered``265 numeric email + URL + behavioral features, gradient boosted
``charngram`` character 3-5 grams - survives typos and word splitting
``wordtfidf`` word 1-2 grams - semantic topic and phrasing
``transformer`` optional DistilBERT head for contextual semantics
============  ==========================================================

``charngram`` deserves a note: it exists specifically because character n-grams
degrade gracefully under the lexical perturbations in the attack suite. Word
models lose the token entirely when ``password`` becomes ``pa ssword``;
character models still see ``pas``, ``ass``, ``ssw``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from phishguard.defenses.normalize import canonicalize
from phishguard.features.assembler import FeatureAssembler
from phishguard.schemas import EmailMessage


@runtime_checkable
class Member(Protocol):
    """Common interface every fusion member implements."""

    name: str
    fitted: bool

    def fit(self, messages: list[EmailMessage], y: np.ndarray) -> Any: ...
    def score(self, messages: list[EmailMessage]) -> np.ndarray: ...


# --------------------------------------------------------------------------
@dataclass(slots=True)
class EngineeredMember:
    """Gradient-boosted trees over the full engineered feature vector.

    ``HistGradientBoostingClassifier`` is chosen over a linear model because
    the signal is genuinely interactive - a new domain is unremarkable, and a
    credential request is unremarkable, but a new domain making a credential
    request at 03:00 is not - and over a random forest because it trains in
    seconds on CPU and handles the mixed scale of these features natively
    without a standardisation step that would have to be kept in sync at
    serving time.
    """

    name: str = "engineered"
    assembler: FeatureAssembler = field(default_factory=FeatureAssembler)
    clf: HistGradientBoostingClassifier | None = None
    fitted: bool = False
    random_state: int = 20260907

    def fit(self, messages: list[EmailMessage], y: np.ndarray) -> EngineeredMember:
        X = self.assembler.transform(messages)
        self.clf = HistGradientBoostingClassifier(
            max_iter=320,
            learning_rate=0.07,
            max_leaf_nodes=31,
            min_samples_leaf=20,
            l2_regularization=1.0,
            early_stopping=True,
            validation_fraction=0.12,
            n_iter_no_change=25,
            random_state=self.random_state,
        )
        self.clf.fit(X, y)
        self.fitted = True
        return self

    def score(self, messages: list[EmailMessage]) -> np.ndarray:
        return self.score_matrix(self.assembler.transform(messages))

    def score_matrix(self, X: np.ndarray) -> np.ndarray:
        """Score a pre-computed feature matrix (used by the explainer)."""
        if not self.fitted or self.clf is None:
            raise RuntimeError("EngineeredMember.score called before fit")
        if X.shape[0] == 0:
            return np.zeros(0, dtype=np.float64)
        return self.clf.predict_proba(X)[:, 1]


# --------------------------------------------------------------------------
def available_memory_mb() -> float | None:
    """Best-effort memory budget, honouring a container limit if one is set.

    Used only to shrink the vectorisers on very small machines. Returns
    ``None`` when the platform will not say, in which case nothing is changed.
    """
    import os
    from pathlib import Path

    candidates: list[float] = []
    for path in ("/sys/fs/cgroup/memory.max",
                 "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            raw = Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if raw in {"max", ""}:
            continue
        try:
            value = int(raw)
        except ValueError:
            continue
        if value < (1 << 62):
            candidates.append(value / (1024.0 * 1024.0))
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    candidates.append(int(line.split()[1]) / 1024.0)
                    break
    except OSError:
        pass
    if not candidates:
        try:
            pages, size = os.sysconf("SC_AVPHYS_PAGES"), os.sysconf("SC_PAGE_SIZE")
            if pages > 0 and size > 0:
                candidates.append(pages * size / (1024.0 * 1024.0))
        except (ValueError, OSError, AttributeError):
            return None
    return min(candidates) if candidates else None


def _memory_scaled(max_features: int) -> int:
    """Shrink the vocabulary on machines that cannot afford the full one.

    Measured peak for a full training run at n=12000 is roughly 380 MB, so this
    never triggers on an ordinary laptop or on the shipped container. It exists
    for the 512 MB cloud instance, where the honest choice is a slightly smaller
    vocabulary rather than an out-of-memory kill halfway through training.
    """
    budget = available_memory_mb()
    if budget is None or budget >= 1200:
        return max_features
    if budget >= 800:
        return max(max_features // 2, 20_000)
    return max(max_features // 4, 10_000)


@dataclass(slots=True)
class TextMember:
    """TF-IDF + calibrated linear model over one text view.

    Linear on purpose: the coefficients give exact per-token attributions with
    no approximation, which is what the analyst evidence card is built from.
    """

    name: str
    analyzer: str = "char_wb"
    ngram_range: tuple[int, int] = (3, 5)
    max_features: int = 200_000
    min_df: int = 2
    C: float = 4.0
    use_canonical: bool = True
    vectorizer: TfidfVectorizer | None = None
    clf: LogisticRegression | None = None
    fitted: bool = False

    def _texts(self, messages: list[EmailMessage]) -> list[str]:
        if self.use_canonical:
            return [canonicalize(m.text) for m in messages]
        return [m.text for m in messages]

    def fit(self, messages: list[EmailMessage], y: np.ndarray) -> TextMember:
        budgeted = _memory_scaled(self.max_features)
        if budgeted != self.max_features:
            import logging

            logging.getLogger("phishguard.models").warning(
                "low memory: reducing %s vocabulary from %d to %d features",
                self.name, self.max_features, budgeted,
            )
        self.vectorizer = TfidfVectorizer(
            analyzer=self.analyzer,
            ngram_range=self.ngram_range,
            min_df=self.min_df,
            max_features=budgeted,
            sublinear_tf=True,
            lowercase=True,
        )
        X = self.vectorizer.fit_transform(self._texts(messages))
        self.clf = LogisticRegression(
            max_iter=3000, C=self.C, class_weight="balanced", solver="liblinear"
        )
        self.clf.fit(X, y)
        self.fitted = True
        return self

    def score(self, messages: list[EmailMessage]) -> np.ndarray:
        if not self.fitted or self.vectorizer is None or self.clf is None:
            raise RuntimeError(f"TextMember({self.name}).score called before fit")
        X = self.vectorizer.transform(self._texts(messages))
        return self.clf.predict_proba(X)[:, 1]

    def token_contributions(self, message: EmailMessage, top_k: int = 8) -> list[dict[str, Any]]:
        """Exact per-feature contributions ``coef_j * x_j`` for one message."""
        if not self.fitted or self.vectorizer is None or self.clf is None:
            return []
        X = self.vectorizer.transform(self._texts([message]))
        coefs = self.clf.coef_[0]
        row = X.tocoo()
        contribs = [(int(c), float(v) * float(coefs[c])) for c, v in zip(row.col, row.data)]
        contribs.sort(key=lambda t: -abs(t[1]))
        names = self.vectorizer.get_feature_names_out()
        return [
            {"token": str(names[idx]).strip(), "contribution": round(val, 5)}
            for idx, val in contribs[:top_k]
            if str(names[idx]).strip()
        ]


def char_ngram_member(**kwargs: Any) -> TextMember:
    """Character 3-5 grams over canonicalized text."""
    return TextMember(
        name="charngram", analyzer="char_wb", ngram_range=(3, 5),
        max_features=200_000, min_df=3, C=4.0, **kwargs,
    )


def word_tfidf_member(**kwargs: Any) -> TextMember:
    """Word 1-2 grams over canonicalized text."""
    return TextMember(
        name="wordtfidf", analyzer="word", ngram_range=(1, 2),
        max_features=80_000, min_df=2, C=4.0, **kwargs,
    )


# --------------------------------------------------------------------------
@dataclass(slots=True)
class TransformerMember:
    """Optional DistilBERT head.

    Guarded: if ``torch``/``transformers`` are not installed, or no GPU makes
    fine-tuning impractical, the member reports itself unavailable and the
    fusion proceeds with the remaining views. The system is designed so that
    this is a genuine optional upgrade, not a hidden hard dependency.
    """

    name: str = "transformer"
    model_name: str = "distilbert-base-uncased"
    epochs: int = 2
    max_len: int = 256
    batch_size: int = 16
    lr: float = 3e-5
    fitted: bool = False
    _pipeline: Any = field(default=None, repr=False)

    @staticmethod
    def available() -> bool:
        try:
            import torch  # noqa: F401
            import transformers  # noqa: F401
        except Exception:  # noqa: BLE001
            return False
        return True

    def fit(self, messages: list[EmailMessage], y: np.ndarray) -> TransformerMember:
        if not self.available():
            raise RuntimeError(
                "transformer member requires the 'transformer' extra: "
                "pip install '.[transformer]'"
            )
        import torch
        from torch.utils.data import DataLoader, TensorDataset
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        tok = AutoTokenizer.from_pretrained(self.model_name)
        model = AutoModelForSequenceClassification.from_pretrained(
            self.model_name, num_labels=2
        )
        device = "cuda" if torch.cuda.is_available() else "cpu"
        model.to(device)

        enc = tok(
            [canonicalize(m.text)[: self.max_len * 6] for m in messages],
            truncation=True, padding="max_length", max_length=self.max_len,
            return_tensors="pt",
        )
        ds = TensorDataset(
            enc["input_ids"], enc["attention_mask"],
            torch.tensor(np.asarray(y), dtype=torch.long),
        )
        loader = DataLoader(ds, batch_size=self.batch_size, shuffle=True)
        opt = torch.optim.AdamW(model.parameters(), lr=self.lr)
        model.train()
        for _ in range(self.epochs):
            for ids, mask, labels in loader:
                opt.zero_grad()
                out = model(
                    input_ids=ids.to(device), attention_mask=mask.to(device),
                    labels=labels.to(device),
                )
                out.loss.backward()
                opt.step()
        model.eval()
        self._pipeline = (tok, model, device)
        self.fitted = True
        return self

    def score(self, messages: list[EmailMessage]) -> np.ndarray:
        if not self.fitted or self._pipeline is None:
            raise RuntimeError("TransformerMember.score called before fit")
        import torch

        tok, model, device = self._pipeline
        out = np.empty(len(messages), dtype=np.float64)
        with torch.no_grad():
            for start in range(0, len(messages), 64):
                chunk = messages[start : start + 64]
                enc = tok(
                    [canonicalize(m.text)[: self.max_len * 6] for m in chunk],
                    truncation=True, padding="max_length", max_length=self.max_len,
                    return_tensors="pt",
                )
                logits = model(
                    input_ids=enc["input_ids"].to(device),
                    attention_mask=enc["attention_mask"].to(device),
                ).logits
                probs = torch.softmax(logits, dim=-1)[:, 1].cpu().numpy()
                out[start : start + len(chunk)] = probs
        return out

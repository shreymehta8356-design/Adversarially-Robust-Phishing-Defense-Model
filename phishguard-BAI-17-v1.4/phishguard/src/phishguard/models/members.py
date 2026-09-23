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

import weakref
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
    for path in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
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


#: ``get_feature_names_out()`` rebuilds and sorts the whole vocabulary on every
#: call -- tens of thousands of n-grams, ~24 ms -- and evidence generation used
#: to call it once per explained message, which made it more than half the
#: cost of an explanation. The names are fixed once a vectoriser is fitted, so
#: they are computed once per vectoriser and kept here. Keyed weakly on the
#: vectoriser object itself: a refit builds a new vectoriser, so stale names
#: can never be served, and no field is added to TextMember (which would break
#: unpickling models saved before this cache existed).
_FEATURE_NAMES: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


def _feature_names(vectorizer: TfidfVectorizer) -> np.ndarray:
    names = _FEATURE_NAMES.get(vectorizer)
    if names is None:
        names = vectorizer.get_feature_names_out()
        _FEATURE_NAMES[vectorizer] = names
    return names


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
                self.name,
                self.max_features,
                budgeted,
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
        contribs = [
            (int(c), float(v) * float(coefs[c])) for c, v in zip(row.col, row.data, strict=False)
        ]
        contribs.sort(key=lambda t: -abs(t[1]))
        names = _feature_names(self.vectorizer)
        return [
            {"token": str(names[idx]).strip(), "contribution": round(val, 5)}
            for idx, val in contribs[:top_k]
            if str(names[idx]).strip()
        ]


def char_ngram_member(**kwargs: Any) -> TextMember:
    """Character 3-5 grams over canonicalized text."""
    return TextMember(
        name="charngram",
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=200_000,
        min_df=3,
        C=4.0,
        **kwargs,
    )


def word_tfidf_member(**kwargs: Any) -> TextMember:
    """Word 1-2 grams over canonicalized text."""
    return TextMember(
        name="wordtfidf",
        analyzer="word",
        ngram_range=(1, 2),
        max_features=80_000,
        min_df=2,
        C=4.0,
        **kwargs,
    )


# --------------------------------------------------------------------------
@dataclass(slots=True)
class TransformerMember:
    """Optional DistilBERT head: a fifth reader that understands wording in context.

    Guarded: if ``torch``/``transformers`` are not installed the member reports
    itself unavailable and the fusion proceeds with the four core views. The
    system is designed so that this is a genuine optional upgrade, not a hidden
    hard dependency. It fine-tunes on a GPU when one is present (a 4 GB card
    is enough at the defaults) and on CPU otherwise, slower.

    It is still a *text* reader: it improves the channel the attacker fully
    controls and leaves the behavioural argument untouched, which is why the
    dossier measures it under attack rather than only on clean mail.
    """

    name: str = "transformer"
    model_name: str = "distilbert-base-uncased"
    epochs: int = 2
    max_len: int = 256
    batch_size: int = 16
    lr: float = 3e-5
    #: Cap on fine-tuning examples: a class-balanced sample keeps a 9 000
    #: message corpus to a few minutes on a laptop GPU.
    max_train: int = 4000
    seed: int = 20260907
    fitted: bool = False
    _pipeline: Any = field(default=None, repr=False)
    _state: dict[str, Any] | None = field(default=None, repr=False)

    @staticmethod
    def available() -> bool:
        try:
            import torch  # noqa: F401
            import transformers  # noqa: F401
        except Exception:  # noqa: BLE001
            return False
        return True

    @staticmethod
    def _device() -> str:
        import torch

        return "cuda" if torch.cuda.is_available() else "cpu"

    def _load_pretrained(self) -> tuple[Any, Any]:
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        try:
            tok = AutoTokenizer.from_pretrained(self.model_name)
            model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name, num_labels=2
            )
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"could not load {self.model_name!r}: the first run downloads about 260 MB "
                "from huggingface.co, so this machine needs internet once "
                f"(then it is cached). Underlying error: {exc}"
            ) from exc
        return tok, model

    def _texts(self, messages: list[EmailMessage]) -> list[str]:
        return [canonicalize(m.text)[: self.max_len * 6] for m in messages]

    def fit(self, messages: list[EmailMessage], y: np.ndarray) -> TransformerMember:
        if not self.available():
            raise RuntimeError(
                "transformer member requires the 'transformer' extra: pip install '.[transformer]'"
            )
        import torch
        from torch.utils.data import DataLoader, TensorDataset

        y = np.asarray(y).astype(int)
        rng = np.random.default_rng(self.seed)
        idx = np.arange(len(messages))
        if len(idx) > self.max_train:
            # Class-balanced subsample so the cap does not silently drop the
            # minority class.
            per_class = self.max_train // 2
            keep = []
            for label in (0, 1):
                pool = idx[y == label]
                keep.extend(rng.choice(pool, size=min(per_class, len(pool)), replace=False))
            idx = np.sort(np.asarray(keep))
        sample = [messages[i] for i in idx]
        y_sample = y[idx]

        tok, model = self._load_pretrained()
        device = self._device()
        model.to(device)
        torch.manual_seed(self.seed)

        enc = tok(
            self._texts(sample),
            truncation=True,
            padding="max_length",
            max_length=self.max_len,
            return_tensors="pt",
        )
        ds = TensorDataset(
            enc["input_ids"],
            enc["attention_mask"],
            torch.tensor(y_sample, dtype=torch.long),
        )
        loader = DataLoader(ds, batch_size=self.batch_size, shuffle=True)
        opt = torch.optim.AdamW(model.parameters(), lr=self.lr)
        use_amp = device == "cuda"
        scaler = torch.cuda.amp.GradScaler(enabled=use_amp)
        model.train()
        for _ in range(self.epochs):
            for ids, mask, labels in loader:
                opt.zero_grad(set_to_none=True)
                with torch.autocast(device_type="cuda", enabled=use_amp):
                    out = model(
                        input_ids=ids.to(device),
                        attention_mask=mask.to(device),
                        labels=labels.to(device),
                    )
                scaler.scale(out.loss).backward()
                scaler.step(opt)
                scaler.update()
        model.eval()
        self._pipeline = (tok, model, device)
        self._state = None
        self.fitted = True
        return self

    # -- persistence: weights travel as CPU tensors, the device is chosen on load
    def __getstate__(self) -> dict[str, Any]:
        state = {
            "name": self.name,
            "model_name": self.model_name,
            "epochs": self.epochs,
            "max_len": self.max_len,
            "batch_size": self.batch_size,
            "lr": self.lr,
            "max_train": self.max_train,
            "seed": self.seed,
            "fitted": self.fitted,
            "weights": None,
        }
        if self._pipeline is not None:
            _, model, _ = self._pipeline
            state["weights"] = {k: v.detach().cpu() for k, v in model.state_dict().items()}
        elif self._state is not None:
            state["weights"] = self._state
        return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        for key in (
            "name",
            "model_name",
            "epochs",
            "max_len",
            "batch_size",
            "lr",
            "max_train",
            "seed",
        ):
            if key in state:
                object.__setattr__(self, key, state[key])
        object.__setattr__(self, "fitted", bool(state.get("fitted", False)))
        object.__setattr__(self, "_pipeline", None)
        object.__setattr__(self, "_state", state.get("weights"))

    def _ensure_loaded(self) -> tuple[Any, Any, str]:
        if self._pipeline is None:
            if self._state is None:
                raise RuntimeError("TransformerMember.score called before fit")
            tok, model = self._load_pretrained()
            model.load_state_dict(self._state)
            device = self._device()
            model.to(device).eval()
            self._pipeline = (tok, model, device)
        return self._pipeline

    def score(self, messages: list[EmailMessage]) -> np.ndarray:
        if not self.fitted:
            raise RuntimeError("TransformerMember.score called before fit")
        import torch

        tok, model, device = self._ensure_loaded()
        out = np.empty(len(messages), dtype=np.float64)
        with torch.no_grad():
            for start in range(0, len(messages), 64):
                chunk = messages[start : start + 64]
                enc = tok(
                    self._texts(chunk),
                    truncation=True,
                    padding=True,
                    max_length=self.max_len,
                    return_tensors="pt",
                )
                with torch.autocast(device_type="cuda", enabled=device == "cuda"):
                    logits = model(
                        input_ids=enc["input_ids"].to(device),
                        attention_mask=enc["attention_mask"].to(device),
                    ).logits
                probs = torch.softmax(logits.float(), dim=-1)[:, 1].cpu().numpy()
                out[start : start + len(chunk)] = probs
        return out

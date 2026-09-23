"""Baselines - the comparison the acceptance gates require.

Two of them, because they answer different questions.

``RuleBaseline`` (B0) is the *manual process* baseline: a transparent weighted
checklist of the heuristics a security analyst would apply by hand, with no
learning at all. It is what the organisation already has, and the innovation
layer has to beat it to be worth deploying. It also doubles as a fusion member,
where it contributes a view no learned model has: it cannot be moved by
distributional drift because it has no distribution.

``TfidfBaseline`` (B1) is the *standard practice* baseline: bag-of-words plus
logistic regression, the approach most phishing-detection papers still report.
Beating it is the bar for claiming the tri-modal design earns its complexity.

Both expose the same ``fit``/``score`` interface as every other fusion member.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from phishguard.defenses.normalize import canonicalize
from phishguard.features.email import email_features
from phishguard.features.urls import aggregate_link_features, extract_links
from phishguard.schemas import EmailMessage


@dataclass(slots=True)
class Rule:
    """One analyst heuristic: a named condition with a weight in log-odds."""

    rule_id: str
    description: str
    weight: float
    feature: str
    threshold: float = 0.5
    #: ``ge`` fires when value >= threshold; ``le`` when value <= threshold.
    op: str = "ge"

    def fires(self, features: dict[str, float]) -> bool:
        value = features.get(self.feature, 0.0)
        return value >= self.threshold if self.op == "ge" else value <= self.threshold


#: The checklist. Weights are log-odds contributions chosen to reflect how much
#: an experienced analyst would move on each signal alone; they are not fitted,
#: which is the point - this arm must stay a genuine "no machine learning"
#: comparison.
RULES: tuple[Rule, ...] = (
    Rule("R01", "Display name claims a brand the sender domain does not own",
         1.5, "hdr_display_brand_domain_mismatch"),
    Rule("R02", "Sender domain is a near-miss typosquat of a known brand",
         1.7, "hdr_is_lookalike"),
    Rule("R03", "Reply-To points at a different domain than From",
         0.9, "hdr_replyto_domain_mismatch"),
    Rule("R04", "Return-Path disagrees with From", 0.5, "hdr_returnpath_domain_mismatch"),
    Rule("R05", "SPF failed", 0.7, "hdr_spf_fail"),
    Rule("R06", "DMARC failed", 0.8, "hdr_dmarc_fail"),
    Rule("R07", "Sender domain uses a high-abuse TLD", 1.1, "hdr_sender_high_risk_tld"),
    Rule("R08", "Sender domain is disposable", 1.4, "hdr_sender_disposable"),
    Rule("R09", "A link impersonates a brand it does not belong to",
         1.8, "link_any_brand_impersonation"),
    Rule("R10", "A link's visible text points somewhere other than its href",
         1.6, "link_text_shows_url_mismatch"),
    Rule("R11", "A link uses a bare IP address as its host", 1.3, "link_any_ip_host"),
    Rule("R12", "A link is wrapped in a URL shortener", 0.7, "link_any_shortener"),
    Rule("R13", "A link is hosted on free/disposable infrastructure",
         0.9, "link_any_free_hosting"),
    Rule("R14", "A link carries an open-redirect parameter", 0.8, "link_any_redirect_param"),
    Rule("R15", "A link uses punycode", 1.0, "link_any_punycode"),
    Rule("R16", "Body asks for credentials", 0.8, "body_lex_credential", 3.0),
    Rule("R17", "Body applies deadline pressure", 0.7, "body_urgency_phrases", 1.0),
    Rule("R18", "Body threatens account consequences", 0.8, "body_lex_threat", 3.0),
    Rule("R19", "Generic greeting rather than the recipient's name",
         0.6, "body_generic_greeting", 1.0),
    Rule("R20", "HTML contains a password input", 1.9, "html_password_input"),
    Rule("R21", "HTML contains hidden or zero-size elements", 0.7, "html_hidden_style_count", 1.0),
    Rule("R22", "Attachment is executable", 2.0, "att_executable", 1.0),
    Rule("R23", "Attachment is macro-enabled", 1.4, "att_macro_enabled", 1.0),
    Rule("R24", "Attachment uses a double extension", 2.0, "att_double_extension", 1.0),
    Rule("R25", "Text contains invisible characters", 1.2, "obf_zero_width_count", 1.0),
    Rule("R26", "Words mix character scripts (homoglyph obfuscation)",
         1.5, "obf_mixed_script_words", 1.0),
    Rule("R27", "Subject is shouted in capitals", 0.5, "subj_all_caps_words", 2.0),
    Rule("R28", "Reward or prize framing", 0.7, "body_lex_reward", 3.0),
    # Mitigating evidence - an analyst lowers suspicion on these.
    Rule("R29", "All three authentication checks passed", -0.9, "hdr_auth_score", 0.99),
    Rule("R30", "Every link points at a brand's genuine domain",
         -1.0, "link_official_brand_ratio", 0.99),
    Rule("R31", "Message carries an unsubscribe footer", -0.5, "body_unsubscribe_present"),
    Rule("R32", "Established two-way correspondence with this sender",
         -1.2, "beh_relationship_strength", 0.5),
    Rule("R33", "Sender domain is well established", -0.7, "beh_domain_age_days", 730.0),
    # Behavioral aggravating evidence.
    Rule("R34", "Newly registered sender domain", 1.2, "beh_young_domain"),
    Rule("R35", "Burst campaign from an unknown sender", 0.9, "beh_campaign_shape", 0.4),
    Rule("R36", "Display name reused across multiple addresses",
         0.8, "beh_display_name_reuse"),
    Rule("R37", "Sender domain previously reported by users", 1.0, "beh_domain_reported"),
)

#: Intercept placing a message with no rule hits at a low prior probability.
RULE_INTERCEPT = -2.2


def _sigmoid(x: np.ndarray | float) -> np.ndarray | float:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -30, 30)))


@dataclass(slots=True)
class RuleBaseline:
    """B0 - a transparent analyst checklist, no learning involved."""

    name: str = "rules"
    rules: tuple[Rule, ...] = RULES
    intercept: float = RULE_INTERCEPT
    fitted: bool = True

    def _features(self, msg: EmailMessage) -> dict[str, float]:
        feats = email_features(msg)
        feats.update(aggregate_link_features(extract_links(msg.body, msg.html_body)))
        from phishguard.features.behavioral import behavioral_features

        feats.update(behavioral_features(msg, msg.behavioral, email_signals=feats))
        return feats

    def explain_one(self, msg: EmailMessage) -> tuple[float, list[dict[str, Any]]]:
        """Score plus the list of rules that fired, ordered by contribution."""
        feats = self._features(msg)
        logit = self.intercept
        fired: list[dict[str, Any]] = []
        for rule in self.rules:
            if rule.fires(feats):
                logit += rule.weight
                fired.append(
                    {
                        "id": rule.rule_id,
                        "description": rule.description,
                        "weight": rule.weight,
                        "feature": rule.feature,
                        "value": round(float(feats.get(rule.feature, 0.0)), 4),
                    }
                )
        fired.sort(key=lambda d: -abs(d["weight"]))
        return float(_sigmoid(logit)), fired

    def fit(self, messages: list[EmailMessage], y: np.ndarray) -> RuleBaseline:  # noqa: ARG002
        """No-op: the checklist is fixed by design so it stays a true baseline."""
        return self

    def score(self, messages: list[EmailMessage]) -> np.ndarray:
        return np.array([self.explain_one(m)[0] for m in messages], dtype=np.float64)

    def catalogue(self) -> list[dict[str, Any]]:
        return [
            {
                "id": r.rule_id, "description": r.description, "weight": r.weight,
                "feature": r.feature, "threshold": r.threshold, "op": r.op,
            }
            for r in self.rules
        ]


@dataclass(slots=True)
class TfidfBaseline:
    """B1 - word-level TF-IDF + logistic regression on subject and body only.

    This is the comparison point that matters academically: it is what a
    conventional phishing classifier looks like. It reads *only* text, which is
    exactly why it collapses under the adversarial suite while the tri-modal
    fusion does not.
    """

    name: str = "tfidf_baseline"
    max_features: int = 60_000
    vectorizer: TfidfVectorizer | None = None
    clf: LogisticRegression | None = None
    fitted: bool = False
    _canonicalize: bool = field(default=False, repr=False)

    def _texts(self, messages: list[EmailMessage]) -> list[str]:
        if self._canonicalize:
            return [canonicalize(m.text) for m in messages]
        return [m.text for m in messages]

    def fit(self, messages: list[EmailMessage], y: np.ndarray) -> TfidfBaseline:
        self.vectorizer = TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            min_df=2,
            max_features=self.max_features,
            sublinear_tf=True,
            strip_accents=None,
        )
        X = self.vectorizer.fit_transform(self._texts(messages))
        self.clf = LogisticRegression(
            max_iter=2000, C=4.0, class_weight="balanced", solver="liblinear"
        )
        self.clf.fit(X, y)
        self.fitted = True
        return self

    def score(self, messages: list[EmailMessage]) -> np.ndarray:
        if not self.fitted or self.vectorizer is None or self.clf is None:
            raise RuntimeError("TfidfBaseline.score called before fit")
        X = self.vectorizer.transform(self._texts(messages))
        return self.clf.predict_proba(X)[:, 1]

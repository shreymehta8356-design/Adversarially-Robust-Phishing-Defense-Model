"""Psycholinguistic lexicons used by the email feature family.

Phishing is a social-engineering artefact before it is a technical one. These
groups follow Cialdini's influence principles plus the credential/payment
vocabulary specific to email fraud, so the feature names map onto something an
analyst can reason about in a review rather than an opaque n-gram index.

Each entry is matched on the *canonicalized* text, so ``p4ssw0rd``,
``pа ssword`` and ``password`` all hit the same bucket.
"""

from __future__ import annotations

import re

URGENCY = frozenset(
    """
urgent urgently immediately immediate asap hurry quick quickly instant
instantly today tonight expire expires expiring expired deadline final
promptly prompt now soon shortly overdue pending rush critical
""".split()
)

#: Multi-word urgency and pressure phrases, matched on the canonicalized text.
URGENCY_PHRASES: tuple[str, ...] = (
    "act now", "right away", "as soon as possible", "within 24 hours",
    "within 48 hours", "last chance", "final notice", "final warning",
    "time sensitive", "limited time", "do not delay", "before it is too late",
    "immediate action", "immediate attention", "action required",
    "response required", "avoid suspension", "failure to comply",
    "your account will be", "will be permanently", "expires today",
)

THREAT = frozenset(
    {
        "suspended", "suspension", "terminated", "termination", "closed",
        "closure", "blocked", "block", "restricted", "restriction", "locked",
        "lock", "disabled", "deactivate", "deactivated", "deactivation",
        "penalty", "fine", "legal", "lawsuit", "prosecution", "police",
        "unauthorized", "unauthorised", "breach", "compromised", "hacked",
        "fraud", "fraudulent", "violation", "violate", "warning", "alert",
        "failure", "failed", "problem", "issue", "risk", "danger", "delete",
        "deletion", "permanently", "consequences",
    }
)

CREDENTIAL = frozenset(
    {
        "password", "passwords", "passcode", "pin", "otp", "credential",
        "credentials", "username", "userid", "login", "log", "signin",
        "sign", "authenticate", "authentication", "verify", "verification",
        "validate", "validation", "confirm", "confirmation", "reactivate",
        "reset", "unlock", "mfa", "2fa", "token", "security", "secure",
        "account", "accounts", "profile", "identity", "kyc", "aadhaar",
        "ssn", "dob",
    }
)

FINANCIAL = frozenset(
    {
        "payment", "payments", "invoice", "invoices", "billing", "bill",
        "refund", "refunds", "transaction", "transactions", "transfer",
        "wire", "deposit", "withdraw", "withdrawal", "balance", "credit",
        "debit", "card", "bank", "banking", "iban", "swift", "upi", "ifsc",
        "salary", "payroll", "bonus", "commission", "tax", "gst", "customs",
        "duty", "fee", "charge", "overdue", "outstanding", "settle",
        "crypto", "bitcoin", "btc", "eth", "wallet", "usdt",
    }
)

REWARD = frozenset(
    {
        "congratulations", "congrats", "winner", "won", "win", "prize",
        "reward", "rewards", "gift", "voucher", "coupon", "cashback",
        "lottery", "jackpot", "selected", "lucky", "free", "exclusive",
        "offer", "discount", "claim", "redeem", "eligible", "qualify",
    }
)

AUTHORITY = frozenset(
    {
        "administrator", "admin", "helpdesk", "support", "team", "department",
        "official", "compliance", "audit", "auditor", "director", "ceo",
        "cfo", "manager", "hr", "payroll", "it", "security", "government",
        "ministry", "authority", "bureau", "commission", "notice", "mandate",
        "policy", "regulation", "regulatory", "required", "mandatory",
    }
)

SECRECY = frozenset(
    {
        "confidential", "confidentially", "private", "privately", "discreet",
        "discreetly", "secret", "secretly", "quietly", "between", "nobody",
        "anyone", "disclose", "sensitive", "internal", "restricted",
    }
)

ACTION = frozenset(
    {
        "click", "clicking", "tap", "press", "follow", "visit", "open",
        "download", "attach", "attached", "attachment", "review", "check",
        "update", "upgrade", "install", "enable", "submit", "complete",
        "fill", "provide", "send", "reply", "respond", "call", "contact",
    }
)

GENERIC_GREETING = (
    "dear customer", "dear user", "dear client", "dear member", "dear sir",
    "dear madam", "dear sir/madam", "dear account holder", "dear valued",
    "dear subscriber", "dear friend", "hello user", "hello customer",
    "attention customer", "to whom it may concern", "dear email user",
)

#: Free-mail providers. A "bank" writing from one of these is a red flag.
FREEMAIL_DOMAINS = frozenset(
    """
gmail.com googlemail.com yahoo.com yahoo.co.in yahoo.co.uk ymail.com
hotmail.com outlook.com live.com msn.com aol.com icloud.com me.com mac.com
protonmail.com proton.me tutanota.com zoho.com gmx.com gmx.net mail.com
mail.ru yandex.com yandex.ru rediffmail.com inbox.com fastmail.com
hushmail.com tempmail.com guerrillamail.com 10minutemail.com mailinator.com
yopmail.com sharklasers.com throwawaymail.com
""".split()
)

#: Disposable-mail providers - never a legitimate corporate sender.
DISPOSABLE_DOMAINS = frozenset(
    """
tempmail.com guerrillamail.com 10minutemail.com mailinator.com yopmail.com
sharklasers.com throwawaymail.com trashmail.com getnada.com dispostable.com
maildrop.cc temp-mail.org fakeinbox.com mintemail.com spamgourmet.com
""".split()
)

#: Attachment extensions by risk tier.
EXEC_EXTENSIONS = frozenset(
    """
exe scr com pif bat cmd vbs vbe js jse wsf wsh ps1 psm1 msi msp hta cpl
jar apk app dmg lnk reg inf iso img vhd chm gadget
""".split()
)
MACRO_EXTENSIONS = frozenset("docm xlsm pptm dotm xltm potm xlam ppam".split())
ARCHIVE_EXTENSIONS = frozenset("zip rar 7z tar gz bz2 xz cab ace arj z lzh".split())
DOC_EXTENSIONS = frozenset("pdf doc docx xls xlsx ppt pptx rtf odt ods odp html htm".split())

#: Legitimate brand registration domains, used for lookalike detection.
BRAND_DOMAINS: dict[str, str] = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "office365": "office.com",
    "outlook": "outlook.com",
    "apple": "apple.com",
    "icloud": "icloud.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "gmail": "gmail.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "linkedin": "linkedin.com",
    "whatsapp": "whatsapp.com",
    "adobe": "adobe.com",
    "dropbox": "dropbox.com",
    "docusign": "docusign.com",
    "zoom": "zoom.us",
    "github": "github.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "ups": "ups.com",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "sbi": "onlinesbi.sbi",
    "axis": "axisbank.com",
    "kotak": "kotak.com",
    "paytm": "paytm.com",
    "phonepe": "phonepe.com",
    "irctc": "irctc.co.in",
    "flipkart": "flipkart.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "chase": "chase.com",
    "hsbc": "hsbc.com",
}

LEXICONS: dict[str, frozenset[str]] = {
    "urgency": URGENCY,
    "threat": THREAT,
    "credential": CREDENTIAL,
    "financial": FINANCIAL,
    "reward": REWARD,
    "authority": AUTHORITY,
    "secrecy": SECRECY,
    "action": ACTION,
}

_TOKEN_RE = re.compile(r"[a-z0-9']+")


def tokenize(text: str) -> list[str]:
    """Lowercase word tokens. Applied to canonicalized text."""
    return _TOKEN_RE.findall((text or "").lower())


def lexicon_counts(tokens: list[str]) -> dict[str, int]:
    """Raw hit counts per lexicon."""
    counts = dict.fromkeys(LEXICONS, 0)
    for tok in tokens:
        for name, vocab in LEXICONS.items():
            if tok in vocab:
                counts[name] += 1
    return counts


def phrase_hits(text: str, phrases: tuple[str, ...]) -> int:
    """Count multi-word phrase occurrences in lowercased text."""
    blob = " ".join((text or "").lower().split())
    return sum(blob.count(p) for p in phrases)


def damerau_levenshtein(a: str, b: str, *, max_distance: int = 4) -> int:
    """Edit distance with transpositions, capped for speed.

    Used to detect registrable lookalikes: ``paypa1.com``, ``paypall.com``,
    ``rnicrosoft.com`` are all within distance 2 of a real brand domain.
    """
    a, b = a or "", b or ""
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    if a == b:
        return 0
    prev_prev: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            cur[j] = min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev_prev[j - 2] + 1)
        if min(cur) > max_distance:
            return max_distance + 1
        prev_prev, prev = prev, cur
    return prev[-1]


def nearest_brand_lookalike(domain: str) -> tuple[str, int]:
    """Closest brand domain and its edit distance (``("", 99)`` when none close)."""
    if not domain:
        return "", 99
    best, best_d = "", 99
    for brand_domain in set(BRAND_DOMAINS.values()):
        if domain == brand_domain:
            return brand_domain, 0
        d = damerau_levenshtein(domain, brand_domain, max_distance=3)
        if d < best_d:
            best, best_d = brand_domain, d
    return (best, best_d) if best_d <= 3 else ("", 99)

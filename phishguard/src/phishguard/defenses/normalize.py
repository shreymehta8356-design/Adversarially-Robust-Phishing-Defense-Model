"""Input canonicalization - defensive control ``D-NORM``.

The single cheapest robustness win in phishing detection is refusing to let an
attacker buy a different feature vector with characters that render
identically. This module folds a message back onto a canonical form before any
feature is computed:

* Unicode confusables (Cyrillic ``а``, Greek ``ο``, fullwidth ``ａ``) -> ASCII
* Zero-width and bidi control characters -> removed
* Combining diacritics (``pаypаl`` with accents) -> stripped
* Leetspeak inside otherwise-alphabetic words (``p4ssw0rd``) -> folded
* Intra-word separators (``p-a-s-s-w-o-r-d``, ``pa ssword``) -> rejoined
* Repeated character runs (``urgeeeent``) -> collapsed to two

Every step is reversible in the sense that we keep the original text too; the
canonical form is an *additional* view, so the model can still see that
obfuscation was present (see ``obfuscation_signals``).

Design note
-----------
Normalization is a defense, not a feature-engineering detail, which is why it
lives here and is switchable. The ablation study in
``phishguard.eval.run_eval`` reports what the system loses without it.
"""

from __future__ import annotations

import re
import unicodedata

# --------------------------------------------------------------------------
# Character tables
# --------------------------------------------------------------------------

#: Characters with no visual footprint that attackers insert to split tokens.
ZERO_WIDTH = "​‌‍⁠﻿᠎­"
#: Bidirectional overrides, used to visually reverse a filename or URL.
BIDI_CONTROL = "‪‫‬‭‮⁦⁧⁨⁩"
INVISIBLE = ZERO_WIDTH + BIDI_CONTROL

#: Confusable -> ASCII. Covers Cyrillic, Greek, fullwidth, mathematical and the
#: handful of Latin-extended letters that carry most real-world homoglyph
#: attacks. Deliberately hand-curated rather than pulled from a large table:
#: every entry here is one an analyst can defend in a viva.
_CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "ѕ": "s", "һ": "h",
    "і": "i", "ј": "j", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
    "ԛ": "q", "г": "r", "т": "t", "у": "y", "х": "x", "ѡ": "w", "ц": "u",
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J",
    "К": "K", "М": "M", "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "У": "Y",
    "Х": "X",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "γ": "y", "ϲ": "c", "ѵ": "v",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y",
    # Armenian / Cherokee / other single-letter lookalikes
    "ѐ": "e", "ǃ": "!", "ɑ": "a", "ɡ": "g", "ɩ": "i", "ʏ": "y", "ʜ": "h",
    "ᴀ": "a", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ᴏ": "o", "ᴘ": "p", "ᴛ": "t",
    # Punctuation and spacing lookalikes
    "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "―": "-", "−": "-",
    "․": ".", "。": ".", "｡": ".", "﹒": ".", "／": "/", "⁄": "/", "∕": "/",
    "：": ":", "；": ";", "＠": "@", "＂": '"', "＇": "'", "‚": ",", "，": ",",
    "“": '"', "”": '"', "‘": "'", "’": "'", "＿": "_", "－": "-",
    " ": " ", " ": " ", " ": " ", " ": " ", "　": " ",
}

#: Leet substitutions folded only when the surrounding token is word-like, so
#: that genuine identifiers such as "H2O" or "2FA" survive.
_LEET = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"}

_FULLWIDTH_OFFSET = 0xFEE0

_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9@$]*[A-Za-z0-9]|[A-Za-z]")
_SEPARATED_RE = re.compile(r"\b(?:[A-Za-z][.\-_*\s]){2,}[A-Za-z]\b")
_RUN_RE = re.compile(r"(.)\1{2,}")
_WS_RE = re.compile(r"[ \t\f]+")


def strip_invisible(text: str) -> str:
    """Remove zero-width and bidi control characters."""
    if not text:
        return text
    return text.translate({ord(c): None for c in INVISIBLE})


def fold_confusables(text: str) -> str:
    """Map homoglyphs and fullwidth forms onto ASCII."""
    if not text:
        return text
    out: list[str] = []
    for ch in text:
        mapped = _CONFUSABLES.get(ch)
        if mapped is not None:
            out.append(mapped)
            continue
        code = ord(ch)
        # Fullwidth ASCII block -> ASCII
        if 0xFF01 <= code <= 0xFF5E:
            out.append(chr(code - _FULLWIDTH_OFFSET))
            continue
        out.append(ch)
    return "".join(out)


def strip_diacritics(text: str) -> str:
    """Decompose and drop combining marks (``pаypál`` -> ``paypal``)."""
    if not text:
        return text
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c))


_DIGIT_RUN_RE = re.compile(r"\d+")


def _defeat_leet(match: re.Match[str]) -> str:
    """Fold ``p4ssw0rd`` while leaving ``sha256`` and ``office365`` intact.

    Leetspeak substitutes single characters *inside* a word, so its digits
    appear as isolated runs of length one. Genuine identifiers put their digits
    in a trailing run (``base64``, ``x509``, ``office365``) or in a long run.
    Folding those would corrupt real tokens and, worse, would make the
    canonical form of a legitimate brand name differ from the brand's own
    spelling.
    """
    token = match.group(0)
    letters = sum(c.isalpha() for c in token)
    digits = sum(c in _LEET for c in token)
    if letters < 3 or digits == 0 or digits > letters:
        return token
    runs = _DIGIT_RUN_RE.findall(token)
    if runs:
        # A trailing digit run, or any run of three or more, means "identifier".
        if token[-1].isdigit() and len(runs[-1]) >= 2:
            return token
        if max(len(r) for r in runs) >= 3:
            return token
    return "".join(_LEET.get(c, c) for c in token)


def defeat_leetspeak(text: str) -> str:
    """Fold digit/symbol substitutions inside otherwise-alphabetic words."""
    if not text:
        return text
    return _WORD_RE.sub(_defeat_leet, text)


def rejoin_separated(text: str) -> str:
    """Collapse ``p-a-s-s-w-o-r-d`` / ``p a s s w o r d`` back into one token."""
    if not text:
        return text

    def _join(m: re.Match[str]) -> str:
        return re.sub(r"[.\-_*\s]", "", m.group(0))

    return _SEPARATED_RE.sub(_join, text)


def collapse_runs(text: str) -> str:
    """``urgeeeeent`` -> ``urgeent`` (two is enough to keep 'ee' words intact)."""
    return _RUN_RE.sub(r"\1\1", text) if text else text


def canonicalize(text: str, *, aggressive: bool = True) -> str:
    """Full canonicalization pipeline used before feature extraction."""
    if not text:
        return ""
    out = unicodedata.normalize("NFKC", text)
    out = strip_invisible(out)
    out = fold_confusables(out)
    out = strip_diacritics(out)
    if aggressive:
        out = rejoin_separated(out)
        out = defeat_leetspeak(out)
        out = collapse_runs(out)
    out = _WS_RE.sub(" ", out)
    return out.strip()


def obfuscation_signals(raw: str) -> dict[str, float]:
    """Measure *how much* canonicalization had to do.

    Evasion effort is itself evidence. A message that needed heavy folding is
    more suspicious than one that arrived clean, so these deltas are fed to the
    model as features rather than being silently discarded.
    """
    if not raw:
        return {
            "obf_zero_width_count": 0.0,
            "obf_bidi_count": 0.0,
            "obf_confusable_ratio": 0.0,
            "obf_diacritic_ratio": 0.0,
            "obf_nonascii_ratio": 0.0,
            "obf_separated_tokens": 0.0,
            "obf_leet_tokens": 0.0,
            "obf_norm_edit_ratio": 0.0,
            "obf_mixed_script_words": 0.0,
        }

    n = max(len(raw), 1)
    zero_width = sum(raw.count(c) for c in ZERO_WIDTH)
    bidi = sum(raw.count(c) for c in BIDI_CONTROL)
    confusables = sum(1 for c in raw if c in _CONFUSABLES)
    nonascii = sum(1 for c in raw if ord(c) > 127)
    decomposed = unicodedata.normalize("NFKD", raw)
    diacritics = sum(1 for c in decomposed if unicodedata.combining(c))
    separated = len(_SEPARATED_RE.findall(raw))

    leet_tokens = 0
    for m in _WORD_RE.finditer(raw):
        tok = m.group(0)
        letters = sum(c.isalpha() for c in tok)
        digits = sum(c in _LEET for c in tok)
        if letters >= 3 and 0 < digits <= letters:
            leet_tokens += 1

    canon = canonicalize(raw)
    edit_ratio = abs(len(raw) - len(canon)) / n

    return {
        "obf_zero_width_count": float(zero_width),
        "obf_bidi_count": float(bidi),
        "obf_confusable_ratio": confusables / n,
        "obf_diacritic_ratio": diacritics / n,
        "obf_nonascii_ratio": nonascii / n,
        "obf_separated_tokens": float(separated),
        "obf_leet_tokens": float(leet_tokens),
        "obf_norm_edit_ratio": edit_ratio,
        "obf_mixed_script_words": float(count_mixed_script_words(raw)),
    }


def _script_of(ch: str) -> str:
    """Coarse script bucket for one character."""
    code = ord(ch)
    if code < 128:
        return "latin" if ch.isalpha() else ""
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return ""
    for script in ("CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC", "CHEROKEE"):
        if name.startswith(script):
            return script.lower()
    if name.startswith("LATIN"):
        return "latin"
    return ""


def count_mixed_script_words(text: str) -> int:
    """Words that mix scripts - the classic homoglyph tell (``pаypal``)."""
    count = 0
    for token in re.split(r"[\s/\\]+", text or ""):
        scripts = {s for s in (_script_of(c) for c in token) if s}
        if len(scripts) > 1:
            count += 1
    return count

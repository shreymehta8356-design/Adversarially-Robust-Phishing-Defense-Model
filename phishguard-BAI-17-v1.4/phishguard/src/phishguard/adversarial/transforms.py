"""Semantic-preserving perturbations, one per taxonomy entry.

Every transform takes an :class:`~phishguard.schemas.EmailMessage` and returns a
modified copy, or ``None`` when it does not apply to that message. Two rules
hold for all of them:

1. **The lure must survive.** A perturbation that deletes the link or the ask
   is not an evasion, it is a broken email. :func:`payload_preserved` enforces
   this, and the attacker discards candidates that fail it.
2. **Only attacker-controlled state may change.** Behavioral transforms may
   move the send time and the pacing; they may not rewrite the recipient's
   correspondence history or the age of the sender's domain. See
   :mod:`phishguard.adversarial.taxonomy` for the capability model.

Transform IDs are stable (``A-UNI-02`` and so on) because they are cited in the
residual-risk register and in the per-transform effectiveness tables.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, replace

import numpy as np

from phishguard.features.urls import extract_links, parse_url
from phishguard.schemas import Attachment, AuthResults, EmailMessage

Rng = np.random.Generator

# --------------------------------------------------------------------------
# Substitution tables
# --------------------------------------------------------------------------
#: Latin -> visually identical characters from other scripts.
_HOMOGLYPHS: dict[str, tuple[str, ...]] = {
    "a": ("а", "ɑ", "α"),
    "c": ("с", "ϲ"),
    "e": ("е", " е".strip(), "ҽ"),
    "i": ("і", "ı", "ɩ"),
    "j": ("ј",),
    "o": ("о", "ο", "ᴏ"),
    "p": ("р", "ρ"),
    "s": ("ѕ",),
    "x": ("х", "χ"),
    "y": ("у", "γ"),
    "h": ("һ",),
    "k": ("κ",),
    "n": ("ո",),
    "b": ("Ь",),
    "d": ("ԁ",),
    "g": ("ɡ",),
    "l": ("ӏ",),
    "A": ("А", "Α"),
    "B": ("В", "Β"),
    "C": ("С",),
    "E": ("Е", "Ε"),
    "H": ("Н", "Η"),
    "I": ("І", "Ι"),
    "K": ("К", "Κ"),
    "M": ("М", "Μ"),
    "O": ("О", "Ο"),
    "P": ("Р", "Ρ"),
    "S": ("Ѕ",),
    "T": ("Т", "Τ"),
    "X": ("Х", "Χ"),
    "Y": ("У", "Υ"),
}
_ZERO_WIDTH = ("​", "‌", "‍", "⁠", "﻿")
_LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "l": "1", "b": "8"}
_KEYBOARD_NEIGHBOURS = {
    "a": "qsz",
    "b": "vgn",
    "c": "xdv",
    "d": "sfce",
    "e": "wrd",
    "f": "dgrv",
    "g": "fhtb",
    "h": "gjyn",
    "i": "uok",
    "j": "hkum",
    "k": "jlim",
    "l": "kop",
    "m": "njk",
    "n": "bhm",
    "o": "ipl",
    "p": "ol",
    "q": "wa",
    "r": "etf",
    "s": "adwx",
    "t": "ryg",
    "u": "yih",
    "v": "cfb",
    "w": "qes",
    "x": "zsc",
    "y": "tuh",
    "z": "asx",
}

#: Meaning-preserving rewrites of the high-signal vocabulary. These are the
#: substitutions a competent operator makes first, because they cost nothing.
_SYNONYMS: dict[str, tuple[str, ...]] = {
    "urgent": ("time-sensitive", "priority", "important"),
    "urgently": ("promptly", "at your earliest convenience", "without delay"),
    "immediately": ("promptly", "as soon as you can", "at your earliest convenience"),
    "verify": ("confirm", "review", "check", "complete"),
    "verification": ("confirmation", "review", "a quick check"),
    "confirm": ("review", "check", "complete"),
    "suspended": ("placed on hold", "paused", "temporarily unavailable"),
    "suspension": ("a temporary hold", "a pause", "an interruption"),
    "blocked": ("restricted", "paused", "limited"),
    "password": ("sign-in details", "access details", "login information"),
    "credentials": ("sign-in details", "access details"),
    "account": ("profile", "record", "membership"),
    "click": ("open", "follow", "use"),
    "expire": ("lapse", "end", "close"),
    "expires": ("lapses", "ends", "closes"),
    "expired": ("lapsed", "ended"),
    "warning": ("notice", "reminder", "update"),
    "alert": ("notice", "update", "message"),
    "unauthorized": ("unrecognised", "unexpected", "unfamiliar"),
    "unauthorised": ("unrecognised", "unexpected", "unfamiliar"),
    "failure": ("a problem", "an issue"),
    "permanently": ("for good", "without recovery"),
    "immediate": ("prompt", "timely"),
    "security": ("account", "access"),
    "final": ("last", "closing"),
    "must": ("will need to", "should"),
    "required": ("needed", "requested"),
}

#: Innocuous sentences copied from legitimate corporate mail. Padding with
#: these shifts the document's overall vocabulary distribution without
#: touching the lure.
_BENIGN_PADDING = (
    "Thank you for your continued custom.",
    "This message was generated automatically; please do not reply directly.",
    "Our office hours are Monday to Friday, 9am to 5pm local time.",
    "For reference, your service agreement number is on your last statement.",
    "We have updated our privacy notice; a copy is available on request.",
    "If you have already actioned this, please disregard this message.",
    "A copy of this notice has been added to your document archive.",
    "Please retain this message for your records.",
    "Our support team is available through the usual channels.",
    "This notice is provided in line with our standard service terms.",
)

_REDIRECT_HOSTS = (
    "news-relay.example",
    "cdn-gateway.example",
    "go-track.example",
    "click-out.example",
    "link-svc.example",
)
_SHORTENER_HOSTS = ("bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "is.gd", "t.ly")

_URL_RE = re.compile(r"https?://[^\s<>\"'`\]\)]+", re.I)
_WORD_RE = re.compile(r"\b[A-Za-z][A-Za-z'-]{2,}\b")


# --------------------------------------------------------------------------
# Transform registry
# --------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Transform:
    """One attack primitive."""

    id: str
    family: str
    name: str
    description: str
    fn: Callable[[EmailMessage, Rng], EmailMessage | None]
    #: Which channel it edits - used to report per-channel effectiveness.
    channel: str


def _pick(rng: Rng, seq) -> object:
    return seq[int(rng.integers(0, len(seq)))]


def _sub_words(text: str, rng: Rng, table: dict[str, tuple[str, ...]], rate: float) -> str:
    """Replace matched words with a same-meaning alternative at ``rate``."""

    def repl(m: re.Match[str]) -> str:
        word = m.group(0)
        options = table.get(word.lower())
        if not options or rng.random() > rate:
            return word
        choice = str(_pick(rng, options))
        if word[0].isupper():
            choice = choice[0].upper() + choice[1:]
        return choice

    return _WORD_RE.sub(repl, text)


# ---------------------------------------------------------------- A-LEX ---
def t_synonym_swap(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    subject = _sub_words(msg.subject, rng, _SYNONYMS, 0.85)
    body = _sub_words(msg.body, rng, _SYNONYMS, 0.75)
    if subject == msg.subject and body == msg.body:
        return None
    return msg.with_text(subject=subject, body=body)


def t_typo_injection(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    """Keyboard-adjacent typos in longer words - human-plausible noise."""
    words = _WORD_RE.findall(msg.body)
    long_words = [w for w in words if len(w) >= 6]
    if not long_words:
        return None
    body = msg.body
    for word in long_words[:12]:
        if rng.random() > 0.4:
            continue
        i = int(rng.integers(1, len(word) - 1))
        neighbours = _KEYBOARD_NEIGHBOURS.get(word[i].lower(), "")
        if not neighbours:
            continue
        typo = word[:i] + str(_pick(rng, neighbours)) + word[i + 1 :]
        body = body.replace(word, typo, 1)
    return msg.with_text(body=body) if body != msg.body else None


def t_benign_padding(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    """Dilute the lure with legitimate-sounding filler."""
    n = int(rng.integers(2, 5))
    picks = [str(_pick(rng, _BENIGN_PADDING)) for _ in range(n)]
    return msg.with_text(body=msg.body + "\n\n" + "\n".join(dict.fromkeys(picks)))


def t_tone_softening(msg: EmailMessage, rng: Rng) -> EmailMessage | None:  # noqa: ARG001
    """Remove shouting, exclamation marks and generic salutations."""
    subject = re.sub(r"!+", "", msg.subject)
    subject = re.sub(
        r"\b(URGENT|IMPORTANT|ALERT|WARNING|FINAL NOTICE)\b[: ]*", "", subject, flags=re.I
    ).strip()
    if subject and subject.isupper():
        subject = subject.capitalize()
    body = re.sub(r"!{1,}", ".", msg.body)
    body = re.sub(
        r"\b(Dear (Customer|User|Valued Customer|Account Holder|Client|Member|Sir/Madam))\b",
        "Hello",
        body,
        flags=re.I,
    )
    body = re.sub(r"\b([A-Z]{4,})\b", lambda m: m.group(1).capitalize(), body)
    if subject == msg.subject and body == msg.body:
        return None
    return msg.with_text(subject=subject or msg.subject, body=body)


def t_deadline_removal(msg: EmailMessage, rng: Rng) -> EmailMessage | None:  # noqa: ARG001
    """Strip explicit time pressure while keeping the request."""
    patterns = [
        r"within \d+ (?:hours?|days?|working days?)",
        r"\bwithin 24 hours\b",
        r"\bimmediately\b",
        r"\bright away\b",
        r"\bfinal (?:notice|warning|reminder)\b",
        r"\bexpires? (?:today|soon)\b",
        r"\bact now\b",
        r"\bdo not delay\b",
        r"\bbefore it is too late\b",
        r"\bfailure to (?:comply|respond)[^.]*\.",
        r"\b(?:will be )?permanently (?:closed|suspended|deleted)[^.]*\.",
    ]
    body = msg.body
    for p in patterns:
        body = re.sub(p, "", body, flags=re.I)
    body = re.sub(r"[ \t]{2,}", " ", body)
    body = re.sub(r"\n{3,}", "\n\n", body)
    return msg.with_text(body=body.strip()) if body.strip() != msg.body else None


# ---------------------------------------------------------------- A-UNI ---
def t_homoglyph(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    """Swap letters inside trigger words for identical-looking foreign glyphs."""

    def perturb(text: str) -> str:
        out = list(text)
        positions = [i for i, c in enumerate(out) if c in _HOMOGLYPHS]
        if not positions:
            return text
        k = max(1, int(len(positions) * 0.30))
        chosen = rng.choice(np.asarray(positions), size=min(k, len(positions)), replace=False)
        for i in np.atleast_1d(chosen):
            out[int(i)] = str(_pick(rng, _HOMOGLYPHS[out[int(i)]]))
        return "".join(out)

    subject, body = perturb(msg.subject), perturb(msg.body)
    if subject == msg.subject and body == msg.body:
        return None
    return msg.with_text(subject=subject, body=body)


def t_zero_width(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    """Insert invisible characters inside high-signal words."""
    targets = (
        "password",
        "verify",
        "account",
        "suspend",
        "urgent",
        "confirm",
        "security",
        "login",
        "bank",
        "payment",
        "click",
        "expire",
    )

    def perturb(text: str) -> str:
        out = text
        for word in targets:
            pattern = re.compile(re.escape(word), re.I)
            if not pattern.search(out):
                continue

            def splice(m: re.Match[str]) -> str:
                w = m.group(0)
                i = max(1, len(w) // 2)
                return w[:i] + str(_pick(rng, _ZERO_WIDTH)) + w[i:]

            out = pattern.sub(splice, out)
        return out

    subject, body = perturb(msg.subject), perturb(msg.body)
    if subject == msg.subject and body == msg.body:
        return None
    return msg.with_text(subject=subject, body=body)


def t_leetspeak(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    def perturb(text: str) -> str:
        def repl(m: re.Match[str]) -> str:
            word = m.group(0)
            if len(word) < 5 or rng.random() > 0.5:
                return word
            return "".join(_LEET.get(c.lower(), c) if rng.random() < 0.45 else c for c in word)

        return _WORD_RE.sub(repl, text)

    body = perturb(msg.body)
    return msg.with_text(body=body) if body != msg.body else None


def t_word_splitting(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    """Break trigger tokens with punctuation or spaces."""
    targets = (
        "password",
        "verify",
        "account",
        "urgent",
        "suspended",
        "confirm",
        "security",
        "login",
        "payment",
        "bank",
    )
    body = msg.body
    for word in targets:
        pattern = re.compile(re.escape(word), re.I)
        if not pattern.search(body):
            continue
        sep = str(_pick(rng, (" ", "-", ".", "_")))

        def splice(m: re.Match[str], _sep: str = sep) -> str:
            w = m.group(0)
            i = int(rng.integers(2, max(3, len(w) - 1)))
            return w[:i] + _sep + w[i:]

        body = pattern.sub(splice, body)
    return msg.with_text(body=body) if body != msg.body else None


def t_diacritics(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    marks = ("́", "̀", "̈", "̄")

    def perturb(text: str) -> str:
        out: list[str] = []
        for ch in text:
            out.append(ch)
            if ch.isalpha() and ch.isascii() and rng.random() < 0.10:
                out.append(str(_pick(rng, marks)))
        return "".join(out)

    body = perturb(msg.body)
    return msg.with_text(body=body) if body != msg.body else None


# ---------------------------------------------------------------- A-URL ---
def _rewrite_urls(msg: EmailMessage, fn: Callable[[str], str]) -> EmailMessage | None:
    body = _URL_RE.sub(lambda m: fn(m.group(0)), msg.body)
    html = _URL_RE.sub(lambda m: fn(m.group(0)), msg.html_body) if msg.html_body else ""
    html = (
        re.sub(
            r'(href\s*=\s*["\'])([^"\']+)(["\'])',
            lambda m: m.group(1) + fn(m.group(2)) + m.group(3),
            html,
            flags=re.I,
        )
        if html
        else ""
    )
    if body == msg.body and html == msg.html_body:
        return None
    return replace(msg, body=body, html_body=html)


def t_shortener_wrap(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    host = str(_pick(rng, _SHORTENER_HOSTS))

    def wrap(url: str) -> str:
        token = "".join(str(_pick(rng, "abcdefghjkmnpqrstuvwxyz23456789")) for _ in range(7))
        return f"https://{host}/{token}"

    return _rewrite_urls(msg, wrap)


def t_open_redirect(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    """Chain through a neutral host so the visible domain looks harmless."""
    relay = str(_pick(rng, _REDIRECT_HOSTS))

    def wrap(url: str) -> str:
        from urllib.parse import quote

        return f"https://{relay}/r?url={quote(url, safe='')}"

    return _rewrite_urls(msg, wrap)


def t_percent_encoding(msg: EmailMessage, rng: Rng) -> EmailMessage | None:  # noqa: ARG001
    def encode(url: str) -> str:
        scheme, sep, rest = url.partition("://")
        if not sep:
            return url
        host, slash, path = rest.partition("/")
        if not slash:
            return url
        encoded = "".join(
            f"%{ord(c):02X}" if c.isalpha() and (i % 3 == 0) else c for i, c in enumerate(path)
        )
        return f"{scheme}://{host}/{encoded}"

    return _rewrite_urls(msg, encode)


def t_subdomain_padding(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    """Bury the real host under reassuring labels."""
    pads = ("secure", "account", "login", "www", "verify", "signin", "auth", "id")

    def pad(url: str) -> str:
        p = parse_url(url)
        if not p.host or p.is_ip:
            return url
        prefix = ".".join(str(_pick(rng, pads)) for _ in range(int(rng.integers(2, 5))))
        rebuilt = f"{p.scheme or 'https'}://{prefix}.{p.host}{p.path or '/'}"
        return rebuilt + (f"?{p.query}" if p.query else "")

    return _rewrite_urls(msg, pad)


def t_path_noise(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    def noisy(url: str) -> str:
        token = "".join(str(_pick(rng, "abcdefghjkmnpqrstuvwxyz0123456789")) for _ in range(18))
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}sid={token}&ref={int(rng.integers(1000, 9999))}"

    return _rewrite_urls(msg, noisy)


def t_strip_https(msg: EmailMessage, rng: Rng) -> EmailMessage | None:  # noqa: ARG001
    """Some kits fall back to http; included so the sign of the effect is measured."""
    return _rewrite_urls(msg, lambda u: u.replace("https://", "http://", 1))


# ------------------------------------------------------------- A-STRUCT ---
def t_html_entities(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    """Encode letters of trigger words as HTML entities."""
    source = msg.html_body or (f"<html><body><p>{msg.body}</p></body></html>" if msg.body else "")
    if not source:
        return None
    targets = ("password", "verify", "account", "urgent", "confirm", "security", "login")
    out = source
    for word in targets:
        pattern = re.compile(re.escape(word), re.I)
        if not pattern.search(out):
            continue
        out = pattern.sub(
            lambda m: "".join(f"&#{ord(c)};" if rng.random() < 0.6 else c for c in m.group(0)),
            out,
        )
    return replace(msg, html_body=out) if out != msg.html_body else None


def t_invisible_spans(msg: EmailMessage, rng: Rng) -> EmailMessage | None:  # noqa: ARG001
    """Split trigger words with zero-size elements that render seamlessly."""
    source = msg.html_body or (f"<html><body><p>{msg.body}</p></body></html>" if msg.body else "")
    if not source:
        return None
    targets = ("password", "verify", "account", "urgent", "suspend", "confirm")
    out = source
    for word in targets:
        pattern = re.compile(re.escape(word), re.I)
        out = pattern.sub(
            lambda m: (
                m.group(0)[: len(m.group(0)) // 2]
                + '<span style="font-size:0">x</span>'
                + m.group(0)[len(m.group(0)) // 2 :]
            ),
            out,
        )
    return replace(msg, html_body=out) if out != msg.html_body else None


def t_text_to_image(msg: EmailMessage, rng: Rng) -> EmailMessage | None:  # noqa: ARG001
    """Move the lure into an image, leaving only the link in text.

    The single most effective structural evasion against text-only models, and
    the reason the URL and behavioral families exist.
    """
    links = extract_links(msg.body, msg.html_body)
    if not links:
        return None
    href = links[0][0]
    html = (
        '<html><body><img src="cid:notice.png" alt="" width="600" height="420">'
        f'<br><a href="{href}">{href}</a></body></html>'
    )
    return replace(msg, body=f"(view this message in HTML)\n\n{href}", html_body=html)


def t_tag_noise(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    source = msg.html_body or (f"<html><body><p>{msg.body}</p></body></html>" if msg.body else "")
    if not source:
        return None
    noise = "".join(
        f'<div class="c{int(rng.integers(100, 999))}"><span></span></div>'
        for _ in range(int(rng.integers(6, 18)))
    )
    return replace(msg, html_body=source.replace("<body>", f"<body>{noise}", 1))


# ---------------------------------------------------------------- A-HDR ---
def t_drop_replyto(msg: EmailMessage, rng: Rng) -> EmailMessage | None:  # noqa: ARG001
    """Remove the Reply-To divergence that gives the spoof away."""
    if not msg.reply_to:
        return None
    return replace(msg, reply_to="")


def t_clean_display_name(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    """Drop the brand claim from the display name so no mismatch is detectable."""
    addr = msg.sender_address
    if not addr:
        return None
    neutral = str(
        _pick(rng, ("Support", "Notifications", "Customer Service", "Service Desk", "Accounts", ""))
    )
    new_sender = f"{neutral} <{addr}>" if neutral else addr
    if new_sender == msg.sender:
        return None
    return replace(msg, sender=new_sender)


def t_align_auth(msg: EmailMessage, rng: Rng) -> EmailMessage | None:  # noqa: ARG001
    """Publish correct SPF/DKIM/DMARC for the attacker's own throwaway domain.

    Permitted by the capability model: the attacker owns the sending domain, so
    aligning its records costs a DNS entry. What they cannot do is make the
    *brand's* domain send the mail - see ``OOS-1`` in the taxonomy.
    """
    if (msg.auth.spf, msg.auth.dkim, msg.auth.dmarc) == ("pass", "pass", "pass"):
        return None
    return replace(msg, auth=AuthResults(spf="pass", dkim="pass", dmarc="pass"))


def t_normalize_return_path(msg: EmailMessage, rng: Rng) -> EmailMessage | None:  # noqa: ARG001
    if not msg.return_path or msg.return_path_address == msg.sender_address:
        return None
    return replace(msg, return_path=msg.sender)


def t_rename_attachments(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    """Give payloads innocuous names and plausible MIME types."""
    if not msg.attachments:
        return None
    safe = ("statement.pdf", "summary.pdf", "details.pdf", "notice.pdf", "report.pdf")
    renamed = [
        Attachment(str(_pick(rng, safe)), "application/pdf", a.size_bytes) for a in msg.attachments
    ]
    return replace(msg, attachments=renamed)


def t_reduce_hops(msg: EmailMessage, rng: Rng) -> EmailMessage | None:  # noqa: ARG001
    if msg.received_hops <= 3:
        return None
    return replace(msg, received_hops=3)


# ---------------------------------------------------------------- A-BEH ---
def _behavioral_copy(msg: EmailMessage, **changes: object) -> EmailMessage:
    return replace(msg, behavioral=replace(msg.behavioral, **changes))


def t_business_hours(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    if 9 <= msg.behavioral.hour_local <= 17 and not msg.behavioral.is_weekend:
        return None
    return _behavioral_copy(msg, hour_local=int(rng.integers(9, 18)), is_weekend=False)


def t_low_and_slow(msg: EmailMessage, rng: Rng) -> EmailMessage | None:  # noqa: ARG001
    """Trade campaign reach for a burst signature that looks like normal mail."""
    if msg.behavioral.burst_count_1h <= 2 and msg.behavioral.recipient_count <= 2:
        return None
    return _behavioral_copy(msg, burst_count_1h=1, recipient_count=1, bcc_count=0)


def t_thread_framing(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    """Imply an existing conversation with a reply-framed subject."""
    if msg.subject.lower().startswith("re:"):
        return None
    framed = replace(msg, subject=f"Re: {msg.subject}")
    return _behavioral_copy(framed, thread_depth=int(rng.integers(1, 5)))


def t_single_identity(msg: EmailMessage, rng: Rng) -> EmailMessage | None:  # noqa: ARG001
    """Stop reusing one display name across many sending addresses."""
    if msg.behavioral.display_name_alias_count <= 1:
        return None
    return _behavioral_copy(msg, display_name_alias_count=1)


# --------------------------------------------------------------------------
# -------------------------------------------------------------- A-TRUST ---
# Payload relocation. The attacker does not disguise the link; they move the
# landing page somewhere whose reputation is genuinely good. This is the
# dominant credential-phishing pattern of the last few years precisely because
# it cannot be answered by blocklisting: the host really is trustworthy.
_TRUST_HOSTS = (
    "forms.gle",
    "docs.google.com",
    "storage.googleapis.com",
    "firebasestorage.googleapis.com",
    "notion.site",
    "webflow.io",
    "netlify.app",
    "pages.dev",
    "sites.google.com",
)
#: Brands whose real domains historically carried open redirectors. The
#: redirect is the attack surface; the brand is the camouflage.
_REDIRECTOR_HOSTS = (
    "www.google.com/url?q=",
    "l.facebook.com/l.php?u=",
    "out.reddit.com/t3?url=",
    "www.youtube.com/redirect?q=",
)
#: Opaque click-tracker shapes. Identical in structure to legitimate ESP mail,
#: which is what makes them expensive to penalise.
_TRACKER_HOSTS = (
    "u2731456.ct.sendgrid.net/ls/click?upn=",
    "links.mailchimp-proxy.example/track/click/",
    "email.mg.customer-notices.example/c/",
)


def _first_link(msg: EmailMessage) -> str:
    links = extract_links(msg.body, msg.html_body)
    return links[0][0] if links else ""


def _swap_link(msg: EmailMessage, old: str, new: str) -> EmailMessage:
    return msg.copy(
        body=msg.body.replace(old, new),
        html_body=msg.html_body.replace(old, new) if msg.html_body else msg.html_body,
    )


def t_trusted_rehost(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    """Re-host the landing page on a reputable content platform."""
    old = _first_link(msg)
    if not old:
        return None
    host = str(_pick(rng, _TRUST_HOSTS))
    slug = "".join(str(_pick(rng, tuple("abcdefghijkmnpqrstuvwxyz0123456789"))) for _ in range(16))
    return _swap_link(msg, old, f"https://{host}/{_pick(rng, ('d', 'view', 's', 'file'))}/{slug}")


def t_trusted_redirect(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    """Launder the destination through a redirector on a trusted domain."""
    from urllib.parse import quote

    old = _first_link(msg)
    if not old or any(h.split("/")[0] in old for h in _REDIRECTOR_HOSTS):
        return None
    prefix = str(_pick(rng, _REDIRECTOR_HOSTS))
    return _swap_link(msg, old, f"https://{prefix}{quote(old, safe='')}")


def t_tracker_wrap(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    """Wrap the link in an opaque click-tracker, as real bulk mail does."""
    old = _first_link(msg)
    if not old or "ct.sendgrid" in old or "/track/click/" in old:
        return None
    prefix = str(_pick(rng, _TRACKER_HOSTS))
    token = "".join(str(_pick(rng, tuple("ABCDEFGHJKLMNPQRSTUVWXYZ23456789"))) for _ in range(24))
    return _swap_link(msg, old, f"https://{prefix}{token}")


# ------------------------------------------------------------ A-CHANNEL ---
# Out-of-band delivery. The payload leaves the message entirely: the victim is
# asked to dial a number or scan an image. Every URL feature reads zero, so a
# URL-centric detector is not weakened by this family -- it is bypassed.
_CALLBACK_LINES = (
    "If you did not authorise this, our billing team can reverse the charge. "
    "Call {number} within 24 hours; cancellations cannot be processed by email.",
    "To dispute this transaction, please call our support line on {number}. "
    "Refunds are not available through the website.",
    "Questions about this renewal? Speak to an advisor on {number}. "
    "Please have your order reference to hand.",
)


def t_callback_number(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    """Replace the link with a phone number the victim is asked to dial."""
    old = _first_link(msg)
    if not old:
        return None
    number = (
        f"+1 (8{int(rng.integers(0, 9))}{int(rng.integers(0, 9))}) "
        f"555-0{int(rng.integers(100, 200))}"
    )
    line = str(_pick(rng, _CALLBACK_LINES)).format(number=number)
    body = msg.body.replace(old, "").replace("\n\n\n", "\n\n").rstrip()
    return msg.copy(body=f"{body}\n\n{line}", html_body="")


def t_qr_substitution(msg: EmailMessage, rng: Rng) -> EmailMessage | None:
    """Move the destination into an inline image, leaving no textual URL."""
    old = _first_link(msg)
    if not old:
        return None
    cid = "".join(str(_pick(rng, tuple("abcdef0123456789"))) for _ in range(10))
    body = msg.body.replace(old, "[QR code image]")
    return msg.copy(
        body=(
            f"{body}\n\nScan the code above with your phone camera to "
            "continue. If it will not scan, reply to this message."
        ),
        html_body=(
            f'<html><body><img src="cid:qr-{cid}" width="220" height="220" alt=""></body></html>'
        ),
    )


TRANSFORMS: tuple[Transform, ...] = (
    Transform(
        "A-LEX-01",
        "A-LEX",
        "Synonym substitution",
        "Replace pressure and credential vocabulary with neutral equivalents",
        t_synonym_swap,
        "text",
    ),
    Transform(
        "A-LEX-02",
        "A-LEX",
        "Typo injection",
        "Keyboard-adjacent character errors in longer words",
        t_typo_injection,
        "text",
    ),
    Transform(
        "A-LEX-03",
        "A-LEX",
        "Benign padding",
        "Append innocuous corporate boilerplate to dilute the lure",
        t_benign_padding,
        "text",
    ),
    Transform(
        "A-LEX-04",
        "A-LEX",
        "Tone softening",
        "Remove shouting, exclamation marks and generic salutations",
        t_tone_softening,
        "text",
    ),
    Transform(
        "A-LEX-05",
        "A-LEX",
        "Deadline removal",
        "Strip explicit time pressure while keeping the request",
        t_deadline_removal,
        "text",
    ),
    Transform(
        "A-UNI-01",
        "A-UNI",
        "Homoglyph substitution",
        "Swap Latin letters for identical-looking Cyrillic and Greek glyphs",
        t_homoglyph,
        "text",
    ),
    Transform(
        "A-UNI-02",
        "A-UNI",
        "Zero-width insertion",
        "Insert invisible characters inside trigger words",
        t_zero_width,
        "text",
    ),
    Transform(
        "A-UNI-03",
        "A-UNI",
        "Leetspeak",
        "Digit-for-letter substitution inside words",
        t_leetspeak,
        "text",
    ),
    Transform(
        "A-UNI-04",
        "A-UNI",
        "Word splitting",
        "Break trigger tokens with punctuation or spaces",
        t_word_splitting,
        "text",
    ),
    Transform(
        "A-UNI-05",
        "A-UNI",
        "Combining diacritics",
        "Add combining marks that alter bytes but not rendering",
        t_diacritics,
        "text",
    ),
    Transform(
        "A-URL-01",
        "A-URL",
        "Shortener wrapping",
        "Replace the destination with a link-shortener URL",
        t_shortener_wrap,
        "url",
    ),
    Transform(
        "A-URL-02",
        "A-URL",
        "Open-redirect chaining",
        "Chain through a neutral host carrying the target in a query parameter",
        t_open_redirect,
        "url",
    ),
    Transform(
        "A-URL-03",
        "A-URL",
        "Percent-encoding",
        "Percent-encode characters in the URL path",
        t_percent_encoding,
        "url",
    ),
    Transform(
        "A-URL-04",
        "A-URL",
        "Subdomain padding",
        "Bury the real host under reassuring subdomain labels",
        t_subdomain_padding,
        "url",
    ),
    Transform(
        "A-URL-05",
        "A-URL",
        "Path and query noise",
        "Append high-entropy tracking parameters",
        t_path_noise,
        "url",
    ),
    Transform(
        "A-URL-06",
        "A-URL",
        "Scheme downgrade",
        "Serve the landing page over http",
        t_strip_https,
        "url",
    ),
    Transform(
        "A-STR-01",
        "A-STRUCT",
        "HTML entity encoding",
        "Encode trigger-word characters as HTML entities",
        t_html_entities,
        "html",
    ),
    Transform(
        "A-STR-02",
        "A-STRUCT",
        "Invisible span injection",
        "Split trigger words with zero-size elements",
        t_invisible_spans,
        "html",
    ),
    Transform(
        "A-STR-03",
        "A-STRUCT",
        "Text-as-image",
        "Move the lure into an image, leaving only the link as text",
        t_text_to_image,
        "html",
    ),
    Transform(
        "A-STR-04",
        "A-STRUCT",
        "Markup noise",
        "Inflate the markup-to-text ratio with empty elements",
        t_tag_noise,
        "html",
    ),
    Transform(
        "A-HDR-01",
        "A-HDR",
        "Drop divergent Reply-To",
        "Remove the Reply-To header that reveals the spoof",
        t_drop_replyto,
        "header",
    ),
    Transform(
        "A-HDR-02",
        "A-HDR",
        "Neutral display name",
        "Remove the brand claim so no display-name mismatch is detectable",
        t_clean_display_name,
        "header",
    ),
    Transform(
        "A-HDR-03",
        "A-HDR",
        "Authentication alignment",
        "Publish valid SPF/DKIM/DMARC for the attacker's own domain",
        t_align_auth,
        "header",
    ),
    Transform(
        "A-HDR-04",
        "A-HDR",
        "Return-Path alignment",
        "Align the envelope sender with the From header",
        t_normalize_return_path,
        "header",
    ),
    Transform(
        "A-HDR-05",
        "A-HDR",
        "Attachment renaming",
        "Give payloads innocuous names and plausible MIME types",
        t_rename_attachments,
        "header",
    ),
    Transform(
        "A-HDR-06",
        "A-HDR",
        "Hop reduction",
        "Shorten the visible relay chain",
        t_reduce_hops,
        "header",
    ),
    Transform(
        "A-BEH-01",
        "A-BEH",
        "Business-hours delivery",
        "Send during the recipient's working hours on a weekday",
        t_business_hours,
        "behavioral",
    ),
    Transform(
        "A-BEH-02",
        "A-BEH",
        "Low-and-slow sending",
        "Drop to single-recipient, non-bursty delivery",
        t_low_and_slow,
        "behavioral",
    ),
    Transform(
        "A-BEH-03",
        "A-BEH",
        "Thread framing",
        "Frame the subject as a reply to imply an existing conversation",
        t_thread_framing,
        "behavioral",
    ),
    Transform(
        "A-BEH-04",
        "A-BEH",
        "Single sending identity",
        "Stop reusing one display name across many addresses",
        t_single_identity,
        "behavioral",
    ),
    Transform(
        "A-TRUST-01",
        "A-TRUST",
        "Reputable re-hosting",
        "Move the landing page onto a content platform with genuine reputation",
        t_trusted_rehost,
        "url",
    ),
    Transform(
        "A-TRUST-02",
        "A-TRUST",
        "Open-redirect laundering",
        "Route the victim through a redirector on a trusted brand domain",
        t_trusted_redirect,
        "url",
    ),
    Transform(
        "A-TRUST-03",
        "A-TRUST",
        "Click-tracker wrapping",
        "Wrap the link in an opaque tracker shaped like legitimate bulk mail",
        t_tracker_wrap,
        "url",
    ),
    Transform(
        "A-CHAN-01",
        "A-CHANNEL",
        "Callback substitution",
        "Replace the link with a phone number, moving the payload off email",
        t_callback_number,
        "structure",
    ),
    Transform(
        "A-CHAN-02",
        "A-CHANNEL",
        "QR substitution",
        "Encode the destination in an inline image so no URL is extractable",
        t_qr_substitution,
        "structure",
    ),
)

TRANSFORM_BY_ID: dict[str, Transform] = {t.id: t for t in TRANSFORMS}


def transforms_for(families: tuple[str, ...] | None = None) -> tuple[Transform, ...]:
    if not families:
        return TRANSFORMS
    wanted = set(families)
    return tuple(t for t in TRANSFORMS if t.family in wanted)


def apply_transform(
    transform_id: str, msg: EmailMessage, rng: Rng | None = None
) -> EmailMessage | None:
    t = TRANSFORM_BY_ID.get(transform_id)
    if t is None:
        raise KeyError(f"unknown transform {transform_id!r}")
    return t.fn(msg, rng or np.random.default_rng())


# --------------------------------------------------------------------------
# Validity
# --------------------------------------------------------------------------
_ASK_PATTERN = re.compile(
    r"\b(verify|confirm|review|update|complete|open|follow|use|click|check|pay|"
    r"restore|secure|proceed|sign|log|reset|unlock|submit|provide|send|reply|"
    r"account|password|payment|invoice|details|code|wallet|refund)\b",
    re.I,
)


#: Payload carriers that survive outside a URL. A message asking the victim to
#: dial a number or scan a code is still a working attack.
_OUT_OF_BAND = re.compile(r"(\+?\d[\d ()\-]{7,}\d)|(\[QR code image\])|(cid:qr-)", re.I)

#: Registered domains of platforms an attacker can legitimately re-host on.
_RELOCATION_HOSTS = frozenset(
    {
        "gle",
        "google.com",
        "googleapis.com",
        "notion.site",
        "webflow.io",
        "netlify.app",
        "pages.dev",
        "sharepoint.com",
        "firebaseapp.com",
        "sendgrid.net",
    }
)


def _still_asks(candidate: EmailMessage) -> bool:
    visible = f"{candidate.subject} {candidate.body} {candidate.html_body}"
    return bool(_ASK_PATTERN.search(visible))


def _not_degenerate(original: EmailMessage, candidate: EmailMessage) -> bool:
    return len(candidate.body.strip()) >= max(40, int(len(original.body) * 0.35))


def payload_preserved(original: EmailMessage, candidate: EmailMessage) -> bool:
    """Is the perturbed message still a working phishing attempt?

    Three conditions, all necessary:

    * **Reachability** - if the original carried links, at least one link must
      survive, and its canonical destination host must still be one of the
      original destinations. Redirect and shortener wrapping pass because the
      victim still lands on the same page; deleting the link does not.
    * **The ask** - some actionable request must remain in the visible text.
    * **Non-degeneracy** - the message may not collapse to near-nothing.

    Without these checks an "attack" that empties the body would be counted as
    a successful evasion, which would make the robustness numbers meaningless.
    """
    from phishguard.features.urls import canonicalize_url

    orig_links = extract_links(original.body, original.html_body)
    cand_links = extract_links(candidate.body, candidate.html_body)

    if orig_links:
        if not cand_links:
            # A-CHANNEL moves the payload out of email entirely: the victim is
            # asked to dial a number or scan a code. Every URL feature reads
            # zero, so this is not a weaker attack -- it is a bypass, and
            # counting it invalid would quietly exclude the family that most
            # cleanly defeats a URL-centric detector. It is only valid when a
            # reachable out-of-band payload is actually present; an empty body
            # still fails.
            if _OUT_OF_BAND.search(f"{candidate.body} {candidate.html_body}"):
                return _still_asks(candidate) and _not_degenerate(original, candidate)
            return False
        orig_hosts = {parse_url(canonicalize_url(h)).registered_domain for h, _ in orig_links} - {
            ""
        }
        cand_hosts = {parse_url(canonicalize_url(h)).registered_domain for h, _ in cand_links} - {
            ""
        }
        # Shortener wrapping legitimately hides the destination offline; accept
        # it as reachable because the victim still arrives at the landing page.
        shortened = any(
            parse_url(h).registered_domain in set(_SHORTENER_HOSTS) for h, _ in cand_links
        )
        # A-TRUST relocates the landing page rather than disguising the link.
        # Re-hosting on a reputable platform, or laundering through an open
        # redirector, is a real attacker capability with a real cost -- an
        # account that gets taken down -- and the victim still arrives on a
        # page the attacker controls. Requiring the original host to survive
        # would mark the dominant credential-phishing pattern of recent years
        # as an invalid attack, which is exactly the wrong answer.
        relocated = any(
            parse_url(h).registered_domain in _RELOCATION_HOSTS
            or any(r.split("/")[0] in h for r in _REDIRECTOR_HOSTS)
            for h, _ in cand_links
        )
        if not shortened and not relocated and orig_hosts and not (orig_hosts & cand_hosts):
            return False

    visible = f"{candidate.subject} {candidate.body} {candidate.html_body}"
    if not _ASK_PATTERN.search(visible):
        return False

    # Non-degeneracy is measured over *all* channels the victim sees, not the
    # plain-text body alone. The text-as-image attack (A-STR-03) legitimately
    # empties the text part while keeping the lure fully intact in the HTML
    # part; scoring it against body length alone rejected 92% of a real and
    # highly effective evasion.
    orig_visible = len(original.subject) + len(original.body.strip()) + len(original.html_body)
    cand_visible = len(candidate.subject) + len(candidate.body.strip()) + len(candidate.html_body)
    if cand_visible < max(20, int(orig_visible * 0.25)):
        return False
    return True


def random_perturbation(
    msg: EmailMessage,
    rng: Rng | None = None,
    *,
    max_steps: int = 3,
    families: tuple[str, ...] | None = None,
) -> EmailMessage:
    """Apply 1-``max_steps`` random valid transforms.

    Used by defensive control ``D-ADVTRAIN`` to build augmented training data.
    Falls back to the original message if nothing valid applies.
    """
    rng = rng or np.random.default_rng()
    pool = transforms_for(families)
    current = msg
    steps = int(rng.integers(1, max_steps + 1))
    for _ in range(steps):
        order = rng.permutation(len(pool))
        for i in order:
            t = pool[int(i)]
            try:
                candidate = t.fn(current, rng)
            except Exception:  # noqa: BLE001, S112 - a broken transform must not stop training
                continue
            if candidate is not None and payload_preserved(msg, candidate):
                current = candidate
                break
    return current

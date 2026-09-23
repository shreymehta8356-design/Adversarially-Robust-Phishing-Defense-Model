"""URL family - extraction, canonicalization and lexical/structural features.

Nothing here touches the network. Every signal is computable from the string
itself, which keeps inference fast, deterministic, offline-capable and free of
the privacy problem that comes with resolving a victim's links.

Three responsibilities:

1. :func:`extract_links` pulls hrefs (and their anchor text) out of plain text
   and HTML, so that link-text/href mismatch is measurable.
2. :func:`canonicalize_url` is defensive control ``D-URL``: it undoes
   percent-encoding, punycode, shortener wrapping and open-redirect nesting so
   that the feature extractor sees the destination the victim actually reaches.
3. :func:`url_features` / :func:`aggregate_link_features` produce the numeric
   signals consumed by the engineered-feature model.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit

from phishguard.defenses.normalize import (
    count_mixed_script_words,
    defeat_leetspeak,
    fold_confusables,
)
from phishguard.features.lexicons import nearest_brand_lookalike

# --------------------------------------------------------------------------
# Reference lists (curated - each entry is defensible in a viva)
# --------------------------------------------------------------------------

#: Public-suffix entries with more than one label. A pragmatic subset of the
#: PSL: the country-code second-level domains that appear in real corpora plus
#: the free app-hosting suffixes attackers use as disposable infrastructure.
MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    """
co.uk org.uk ac.uk gov.uk me.uk net.uk sch.uk
co.in net.in org.in gov.in ac.in edu.in firm.in gen.in ind.in
com.au net.au org.au edu.au gov.au id.au
co.nz net.nz org.nz govt.nz ac.nz
com.br net.br org.br gov.br
com.cn net.cn org.cn gov.cn edu.cn
co.jp ne.jp or.jp ac.jp go.jp
co.kr or.kr ne.kr go.kr
com.sg com.hk com.tw com.my com.ph com.vn com.pk com.bd
com.tr com.mx com.ar com.co com.pe com.ve com.ec com.uy com.do
com.sa com.eg com.ng com.gh com.ua com.pl com.ru org.ru net.ru
co.za co.ke co.tz co.ug co.il co.th co.id
github.io gitlab.io pages.dev workers.dev r2.dev
herokuapp.com azurewebsites.net cloudfront.net amazonaws.com
firebaseapp.com web.app netlify.app vercel.app glitch.me repl.co
onrender.com surge.sh ngrok.io ngrok-free.app trycloudflare.com
000webhostapp.com weebly.com wixsite.com blogspot.com
""".split()
)

#: Suffixes that hand out free, anonymous hosting. Not malicious per se, but a
#: brand login page never legitimately lives on one.
FREE_HOSTING_SUFFIXES: frozenset[str] = frozenset(
    """
github.io gitlab.io pages.dev workers.dev r2.dev herokuapp.com
azurewebsites.net firebaseapp.com web.app netlify.app vercel.app
glitch.me repl.co onrender.com surge.sh ngrok.io ngrok-free.app
trycloudflare.com 000webhostapp.com weebly.com wixsite.com blogspot.com
duckdns.org no-ip.org hopto.org serveo.net localtunnel.me
""".split()
)

#: Link shorteners: they hide the destination, so the presence of one is a
#: signal and the wrapper is unwrapped where the target is embedded.
SHORTENER_DOMAINS: frozenset[str] = frozenset(
    """
bit.ly tinyurl.com goo.gl t.co ow.ly is.gd buff.ly rebrand.ly cutt.ly
shorturl.at tiny.cc rb.gy s.id lnkd.in t.ly bl.ink shorte.st adf.ly
soo.gd u.to clck.ru v.gd qr.ae x.co po.st mcaf.ee db.tt q.gs
""".split()
)

#: TLDs with disproportionate abuse rates (free or near-free registration,
#: weak verification) plus the two TLDs that collide with file extensions.
HIGH_RISK_TLDS: frozenset[str] = frozenset(
    """
tk ml ga cf gq xyz top work click link live icu buzz rest monster bar
cyou sbs cfd quest mom lol zip mov review country kim science party gdn
loan download racing win bid stream date faith cricket accountant men
trade webcam pw su cc ru cn info biz online site space website fun store
shop today world life email support help center autos beauty hair skin
""".split()
)

#: Brands most impersonated in credential phishing (global + Indian banking).
BRAND_TOKENS: frozenset[str] = frozenset(
    """
paypal microsoft office365 office outlook onedrive sharepoint teams azure
apple icloud itunes appleid amazon aws google gmail drive docs youtube
netflix spotify facebook instagram whatsapp meta linkedin twitter x
adobe dropbox docusign zoom slack github gitlab atlassian jira
chase wellsfargo bankofamerica citibank americanexpress amex hsbc barclays
santander lloyds natwest revolut wise
hdfc icici sbi axis kotak pnb yesbank idfc rbl bandhan indusind
paytm phonepe googlepay bhim upi npci rbi incometax gst uidai aadhaar
dhl fedex ups usps bluedart delhivery dtdc ekart
irs hmrc gov nhs medicare
coinbase binance metamask kraken blockchain ledger trezor
steam epicgames roblox discord telegram signal
flipkart myntra swiggy zomato ola uber irctc
""".split()
)

#: Path/query keywords that appear on credential-harvest and payment pages.
SUSPICIOUS_PATH_TOKENS: frozenset[str] = frozenset(
    """
login signin sign-in log-in logon auth authenticate verify verification
validate confirm confirmation secure security update updating account
accounts recover recovery reset unlock unblock suspended limited restricted
billing payment invoice refund reward bonus prize claim gift wallet
webscr cmd session token otp mfa 2fa credential password passwd pwd
customer support helpdesk service portal myaccount id user
""".split()
)

#: Query parameters that carry a nested URL - the open-redirect vector.
REDIRECT_PARAMS: tuple[str, ...] = (
    "url",
    "u",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "next",
    "target",
    "dest",
    "destination",
    "return",
    "returnurl",
    "return_url",
    "continue",
    "goto",
    "link",
    "out",
    "r",
    "q",
    "to",
    "forward",
    "rurl",
    "ref",
)

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HEX_HOST_RE = re.compile(r"^0x[0-9a-f]+$", re.I)
_URL_IN_TEXT_RE = re.compile(
    r"""(?xi)
    \b
    (?:
        (?:https?|ftp)://[^\s<>"'`\]\)]+       # explicit scheme
      | www\.[^\s<>"'`\]\)]+                   # bare www
      | (?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}
        (?:/[^\s<>"'`\]\)]*)?                  # bare host with optional path
    )
    """
)
_ANCHOR_RE = re.compile(
    r"""<a\b[^>]*?href\s*=\s*(?P<q>["']?)(?P<href>[^"'\s>]+)(?P=q)[^>]*>(?P<text>.*?)</a\s*>""",
    re.I | re.S,
)
_TAG_RE = re.compile(r"<[^>]+>")
_TRAILING_PUNCT = ".,;:!?)]}>'\"’”"


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
@dataclass(slots=True)
class UrlParts:
    """Decomposed URL. ``registered_domain`` is eTLD+1."""

    raw: str
    scheme: str = ""
    userinfo: str = ""
    host: str = ""
    port: int = 0
    path: str = ""
    query: str = ""
    fragment: str = ""
    suffix: str = ""
    registered_domain: str = ""
    subdomain: str = ""
    is_ip: bool = False

    @property
    def host_labels(self) -> list[str]:
        return [p for p in self.host.split(".") if p]


def split_public_suffix(host: str) -> tuple[str, str, str]:
    """Return ``(subdomain, registered_domain, suffix)`` for a hostname."""
    host = (host or "").strip(".").lower()
    if not host or _IPV4_RE.match(host):
        return "", host, ""
    labels = host.split(".")
    if len(labels) < 2:
        return "", host, ""
    two = ".".join(labels[-2:])
    three = ".".join(labels[-3:]) if len(labels) >= 3 else ""
    if three and three in MULTI_LABEL_SUFFIXES:
        suffix, rest = three, labels[:-3]
    elif two in MULTI_LABEL_SUFFIXES:
        suffix, rest = two, labels[:-2]
    else:
        suffix, rest = labels[-1], labels[:-1]
    if not rest:
        return "", suffix, suffix
    registered = f"{rest[-1]}.{suffix}"
    subdomain = ".".join(rest[:-1])
    return subdomain, registered, suffix


def parse_url(url: str) -> UrlParts:
    """Permissive URL parse that never raises."""
    raw = (url or "").strip()
    candidate = raw
    if candidate and "//" not in candidate.split("?", 1)[0][:8]:
        candidate = "http://" + candidate
    try:
        sp = urlsplit(candidate)
        scheme = (sp.scheme or "").lower()
        netloc = sp.netloc
        userinfo = ""
        if "@" in netloc:
            userinfo, _, netloc = netloc.rpartition("@")
        port = 0
        host = netloc
        if host.startswith("["):  # IPv6 literal
            close = host.find("]")
            if close != -1:
                maybe_port = host[close + 1 :]
                host = host[: close + 1]
                if maybe_port.startswith(":") and maybe_port[1:].isdigit():
                    port = int(maybe_port[1:])
        elif ":" in host:
            host, _, port_s = host.rpartition(":")
            if port_s.isdigit():
                port = int(port_s)
        host = host.strip().strip(".").lower()
        try:
            if host.startswith("xn--") or ".xn--" in host:
                host = host.encode("ascii", "ignore").decode("idna")
        except Exception:  # noqa: BLE001, S110 - malformed punycode stays as-is
            pass
        sub, reg, suf = split_public_suffix(host)
        return UrlParts(
            raw=raw,
            scheme=scheme,
            userinfo=userinfo,
            host=host,
            port=port,
            path=sp.path or "",
            query=sp.query or "",
            fragment=sp.fragment or "",
            suffix=suf,
            registered_domain=reg,
            subdomain=sub,
            is_ip=bool(_IPV4_RE.match(host)) or host.startswith("["),
        )
    except Exception:  # noqa: BLE001
        return UrlParts(raw=raw)


def canonicalize_url(url: str, *, max_unwrap: int = 3) -> str:
    """Defensive control ``D-URL``.

    Recursively unwraps open-redirect parameters, decodes percent-encoding and
    punycode, folds homoglyphs in the host and normalizes case, so that
    ``https://bit.example/x?u=https%3A%2F%2Fраypal-verify.tk%2Flogin`` and
    ``https://paypal-verify.tk/login`` produce the same features.
    """
    current = (url or "").strip()
    for _ in range(max_unwrap):
        decoded = unquote(current)
        parts = parse_url(decoded)
        nested = ""
        if parts.query:
            try:
                qs = parse_qs(parts.query, keep_blank_values=False)
            except Exception:  # noqa: BLE001
                qs = {}
            for key in REDIRECT_PARAMS:
                for candidate in qs.get(key, []):
                    cand = unquote(candidate).strip()
                    if "." in cand and (cand.startswith("http") or "//" in cand or "/" in cand):
                        cp = parse_url(cand)
                        if cp.registered_domain and cp.registered_domain != parts.registered_domain:
                            nested = cand
                            break
                if nested:
                    break
        if nested:
            current = nested
            continue
        host = fold_confusables(parts.host)
        if not host:
            return decoded
        scheme = parts.scheme or "http"
        port = f":{parts.port}" if parts.port and parts.port not in (80, 443) else ""
        path = parts.path or "/"
        rebuilt = f"{scheme}://{host}{port}{path}"
        if parts.query:
            rebuilt += f"?{parts.query}"
        return rebuilt
    return current


def extract_links(text: str = "", html: str = "") -> list[tuple[str, str]]:
    """Return ``[(href, anchor_text)]`` from HTML anchors and bare-text URLs.

    Anchor text is kept because the gap between what a link *says* and where it
    *goes* is one of the strongest single phishing signals, and it is invisible
    to any model that only reads the body text.
    """
    links: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for m in _ANCHOR_RE.finditer(html or ""):
        href = (m.group("href") or "").strip()
        label = _TAG_RE.sub(" ", m.group("text") or "")
        label = re.sub(r"\s+", " ", label).strip()
        if href and not href.lower().startswith(("mailto:", "tel:", "javascript:", "#")):
            key = (href, label)
            if key not in seen:
                seen.add(key)
                links.append(key)

    stripped_html = _TAG_RE.sub(" ", html or "")
    for blob in (text or "", stripped_html):
        for m in _URL_IN_TEXT_RE.finditer(blob):
            href = m.group(0).rstrip(_TRAILING_PUNCT)
            if not href or "@" in href.split("/")[0] and "://" not in href:
                continue  # looks like a bare email address
            key = (href, "")
            if key not in seen and all(href != h for h, _ in links):
                seen.add(key)
                links.append(key)
    return links


# --------------------------------------------------------------------------
# Features
# --------------------------------------------------------------------------
def shannon_entropy(s: str) -> float:
    """Character entropy - high values flag algorithmically generated hosts."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _brand_hits(blob: str) -> set[str]:
    """Brand tokens present in a URL fragment.

    Matching is done on a leet-folded copy as well as the literal text, so that
    ``paypa1``, ``g00gle`` and ``micr0soft`` are recognised as brand claims
    rather than slipping through as unremarkable strings.
    """
    if not blob:
        return set()
    lowered = blob.lower()
    folded = defeat_leetspeak(lowered)
    hits: set[str] = set()
    for variant in {lowered, folded}:
        tokens = set(re.split(r"[^a-z0-9]+", variant))
        hits |= tokens & BRAND_TOKENS
        hits |= {b for b in BRAND_TOKENS if len(b) >= 5 and b in variant}
    return hits


#: Stable, ordered names of the per-URL features. Order is part of the contract.
URL_FEATURE_NAMES: tuple[str, ...] = (
    "url_length",
    "url_host_length",
    "url_path_length",
    "url_query_length",
    "url_num_dots",
    "url_num_hyphens",
    "url_num_digits",
    "url_digit_ratio",
    "url_num_subdomains",
    "url_num_path_segments",
    "url_num_query_params",
    "url_host_entropy",
    "url_longest_token",
    "url_is_https",
    "url_is_ip_host",
    "url_has_port",
    "url_nonstandard_port",
    "url_has_userinfo",
    "url_has_at_symbol",
    "url_double_slash_in_path",
    "url_is_punycode",
    "url_pct_encoding_ratio",
    "url_has_hex_host",
    "url_is_shortener",
    "url_free_hosting",
    "url_high_risk_tld",
    "url_brand_in_subdomain",
    "url_brand_in_path",
    "url_brand_mismatch",
    "url_suspicious_token_count",
    "url_has_redirect_param",
    "url_mixed_script_host",
    "url_hyphen_in_registered_domain",
    "url_tld_length",
    "url_deep_subdomain",
    "url_unwrap_changed_host",
    "url_brand_lookalike",
    "url_lookalike_distance",
    "url_brand_squat",
    "url_official_brand_domain",
    "url_brand_impersonation",
)


def _is_official_brand_domain(registered_domain: str) -> bool:
    """True when the registered domain is a brand's genuine domain."""
    from phishguard.features.lexicons import BRAND_DOMAINS

    return registered_domain in set(BRAND_DOMAINS.values())


def url_features(url: str, *, canonicalize: bool = True) -> dict[str, float]:
    """Compute the per-URL feature dictionary."""
    original = parse_url(url)
    canon_str = canonicalize_url(url) if canonicalize else url
    p = parse_url(canon_str) if canonicalize else original

    host = p.host
    path = p.path or ""
    query = p.query or ""
    full = canon_str or url or ""
    n = max(len(full), 1)

    labels = p.host_labels
    reg_labels = p.registered_domain.split(".") if p.registered_domain else []
    num_sub = max(len(labels) - len(reg_labels), 0)

    tokens = [t for t in re.split(r"[^A-Za-z0-9]+", full) if t]
    longest_token = max((len(t) for t in tokens), default=0)

    sub_blob = p.subdomain
    path_blob = f"{path} {query}"
    brand_sub = _brand_hits(sub_blob)
    brand_path = _brand_hits(path_blob)
    brand_reg = _brand_hits(p.registered_domain.split(".")[0] if reg_labels else "")

    # Brand mismatch: the brand appears somewhere in the URL but *not* as the
    # registered domain. This is the core impersonation test.
    brand_anywhere = brand_sub | brand_path
    brand_mismatch = bool(brand_anywhere) and not brand_reg

    suspicious = sum(1 for t in SUSPICIOUS_PATH_TOKENS if t in path_blob.lower())
    pct_encoded = (url or "").count("%")

    # Typosquat distance, measured on both the literal and the leet-folded
    # domain so that "paypa1.com" is scored the same as "paypall.com".
    lookalike_dist = min(
        nearest_brand_lookalike(p.registered_domain)[1],
        nearest_brand_lookalike(defeat_leetspeak(p.registered_domain))[1],
    )
    # Brand squatting: a brand token sits inside a registered domain that is not
    # the brand's own ("paypa1-secure.tk", "hdfc-netbanking-alert.xyz").
    official = _is_official_brand_domain(p.registered_domain)
    brand_squat = bool(brand_reg) and not official

    try:
        qs = parse_qs(query, keep_blank_values=True)
    except Exception:  # noqa: BLE001
        qs = {}
    has_redirect = any(k.lower() in REDIRECT_PARAMS for k in qs)

    return {
        "url_length": float(len(full)),
        "url_host_length": float(len(host)),
        "url_path_length": float(len(path)),
        "url_query_length": float(len(query)),
        "url_num_dots": float(host.count(".")),
        "url_num_hyphens": float(full.count("-")),
        "url_num_digits": float(sum(c.isdigit() for c in full)),
        "url_digit_ratio": sum(c.isdigit() for c in full) / n,
        "url_num_subdomains": float(num_sub),
        "url_num_path_segments": float(len([s for s in path.split("/") if s])),
        "url_num_query_params": float(len(qs)),
        "url_host_entropy": shannon_entropy(host),
        "url_longest_token": float(longest_token),
        "url_is_https": 1.0 if p.scheme == "https" else 0.0,
        "url_is_ip_host": 1.0 if p.is_ip else 0.0,
        "url_has_port": 1.0 if p.port else 0.0,
        "url_nonstandard_port": 1.0 if p.port and p.port not in (80, 443) else 0.0,
        "url_has_userinfo": 1.0 if original.userinfo else 0.0,
        "url_has_at_symbol": 1.0 if "@" in (url or "").split("?")[0] else 0.0,
        "url_double_slash_in_path": 1.0 if "//" in path else 0.0,
        "url_is_punycode": 1.0 if "xn--" in (url or "").lower() else 0.0,
        "url_pct_encoding_ratio": pct_encoded / max(len(url or ""), 1),
        "url_has_hex_host": 1.0 if _HEX_HOST_RE.match(host or "") else 0.0,
        "url_is_shortener": 1.0 if original.registered_domain in SHORTENER_DOMAINS else 0.0,
        "url_free_hosting": 1.0 if p.suffix in FREE_HOSTING_SUFFIXES else 0.0,
        "url_high_risk_tld": 1.0 if p.suffix.rsplit(".", 1)[-1] in HIGH_RISK_TLDS else 0.0,
        "url_brand_in_subdomain": float(len(brand_sub)),
        "url_brand_in_path": float(len(brand_path)),
        "url_brand_mismatch": 1.0 if brand_mismatch else 0.0,
        "url_suspicious_token_count": float(suspicious),
        "url_has_redirect_param": 1.0 if has_redirect else 0.0,
        "url_mixed_script_host": float(count_mixed_script_words(original.host)),
        "url_hyphen_in_registered_domain": float(p.registered_domain.count("-")),
        "url_tld_length": float(len(p.suffix.rsplit(".", 1)[-1])),
        "url_deep_subdomain": 1.0 if num_sub >= 3 else 0.0,
        "url_unwrap_changed_host": (
            1.0
            if original.registered_domain and original.registered_domain != p.registered_domain
            else 0.0
        ),
        # Typosquat / homoglyph registration: within a couple of edits of a real
        # brand domain without being it (paypa1.com, rnicrosoft.com, hdfcbnak.com).
        "url_brand_lookalike": 1.0 if 0 < lookalike_dist <= 2 else 0.0,
        "url_lookalike_distance": float(min(lookalike_dist, 9)),
        "url_brand_squat": 1.0 if brand_squat else 0.0,
        "url_official_brand_domain": 1.0 if official else 0.0,
        "url_brand_impersonation": (
            1.0 if (brand_squat or brand_mismatch or 0 < lookalike_dist <= 2) else 0.0
        ),
    }


#: Aggregate-level names produced by :func:`aggregate_link_features`.
LINK_AGG_NAMES: tuple[str, ...] = (
    (
        "link_count",
        "link_unique_domains",
        "link_max_risk_tld",
        "link_any_ip_host",
        "link_any_shortener",
        "link_any_punycode",
        "link_any_brand_mismatch",
        "link_any_free_hosting",
        "link_any_redirect_param",
        "link_any_at_symbol",
        "link_any_brand_lookalike",
        "link_min_lookalike_distance",
        "link_any_brand_squat",
        "link_any_brand_impersonation",
        "link_official_brand_ratio",
        "link_text_href_mismatch",
        "link_text_shows_url_mismatch",
        "link_display_domain_mismatch",
        "link_max_suspicious_tokens",
        "link_mean_length",
        "link_max_length",
        "link_max_subdomains",
        "link_max_host_entropy",
        "link_https_ratio",
        "link_domain_diversity",
    )
    + tuple(f"{n}__max" for n in URL_FEATURE_NAMES)
    + tuple(f"{n}__mean" for n in URL_FEATURE_NAMES)
)


#: Features where 0 is a *meaningful low* value rather than "absent". For a
#: message with no links at all these must fall back to the neutral maximum,
#: not to zero -- otherwise "no links" becomes indistinguishable from "links
#: pointing at the brand's genuine domain", which is the opposite meaning. An
#: earlier revision zero-filled these and the leakage audit duly reported
#: url_lookalike_distance separating the classes at 0.97 AUC.
_DISTANCE_LIKE: dict[str, float] = {
    "url_lookalike_distance__max": 9.0,
    "url_lookalike_distance__mean": 9.0,
    "link_min_lookalike_distance": 9.0,
}


def aggregate_link_features(
    links: list[tuple[str, str]], *, canonicalize: bool = True
) -> dict[str, float]:
    """Roll per-URL features up to one message-level vector.

    ``max`` captures "the single worst link in this email" (what actually
    matters for a decision) and ``mean`` captures "how consistently bad the
    email is", which separates a hijacked newsletter from a purpose-built lure.
    """
    out: dict[str, float] = dict.fromkeys(LINK_AGG_NAMES, 0.0)
    out.update(_DISTANCE_LIKE)
    if not links:
        return out

    per_url: list[dict[str, float]] = []
    domains: list[str] = []
    text_mismatch = 0
    text_url_mismatch = 0

    for href, label in links:
        f = url_features(href, canonicalize=canonicalize)
        per_url.append(f)
        p = parse_url(canonicalize_url(href) if canonicalize else href)
        if p.registered_domain:
            domains.append(p.registered_domain)

        if label:
            label_links = _URL_IN_TEXT_RE.findall(label)
            if label_links or "://" in label or label.lower().startswith("www."):
                lp = parse_url(label.strip())
                if lp.registered_domain and lp.registered_domain != p.registered_domain:
                    text_url_mismatch += 1
            brands_in_label = _brand_hits(label)
            if brands_in_label and not _brand_hits(p.registered_domain):
                text_mismatch += 1

    n = len(per_url)
    for name in URL_FEATURE_NAMES:
        vals = [f[name] for f in per_url]
        out[f"{name}__max"] = max(vals)
        out[f"{name}__mean"] = sum(vals) / n

    uniq = set(domains)
    out.update(
        {
            "link_count": float(n),
            "link_unique_domains": float(len(uniq)),
            "link_max_risk_tld": out["url_high_risk_tld__max"],
            "link_any_ip_host": out["url_is_ip_host__max"],
            "link_any_shortener": out["url_is_shortener__max"],
            "link_any_punycode": out["url_is_punycode__max"],
            "link_any_brand_mismatch": out["url_brand_mismatch__max"],
            "link_any_free_hosting": out["url_free_hosting__max"],
            "link_any_redirect_param": out["url_has_redirect_param__max"],
            "link_any_at_symbol": out["url_has_at_symbol__max"],
            "link_any_brand_lookalike": out["url_brand_lookalike__max"],
            "link_min_lookalike_distance": min(f["url_lookalike_distance"] for f in per_url),
            "link_any_brand_squat": out["url_brand_squat__max"],
            "link_any_brand_impersonation": out["url_brand_impersonation__max"],
            "link_official_brand_ratio": out["url_official_brand_domain__mean"],
            "link_text_href_mismatch": float(text_mismatch),
            "link_text_shows_url_mismatch": float(text_url_mismatch),
            "link_display_domain_mismatch": float(text_mismatch + text_url_mismatch),
            "link_max_suspicious_tokens": out["url_suspicious_token_count__max"],
            "link_mean_length": out["url_length__mean"],
            "link_max_length": out["url_length__max"],
            "link_max_subdomains": out["url_num_subdomains__max"],
            "link_max_host_entropy": out["url_host_entropy__max"],
            "link_https_ratio": out["url_is_https__mean"],
            "link_domain_diversity": len(uniq) / n,
        }
    )
    return out

"""URL family: parsing, canonicalization (D-URL) and features."""

from __future__ import annotations

from phishguard.features.urls import (
    aggregate_link_features,
    canonicalize_url,
    extract_links,
    parse_url,
    split_public_suffix,
    url_features,
)


def test_splits_multi_label_public_suffixes():
    assert split_public_suffix("www.example.co.uk") == ("www", "example.co.uk", "co.uk")
    assert split_public_suffix("mail.example.com") == ("mail", "example.com", "com")
    assert split_public_suffix("example.com") == ("", "example.com", "com")


def test_treats_free_hosting_suffixes_as_public():
    _, registered, suffix = split_public_suffix("evil.pages.dev")
    assert suffix == "pages.dev"
    assert registered == "evil.pages.dev"


def test_canonicalize_unwraps_an_open_redirect():
    wrapped = "https://relay.example/r?url=https%3A%2F%2Fbad-domain.tk%2Flogin"
    assert parse_url(canonicalize_url(wrapped)).registered_domain == "bad-domain.tk"


def test_canonicalize_folds_homoglyphs_in_the_host():
    # Cyrillic 'а' in the host must resolve to the ASCII form.
    assert "paypal" in canonicalize_url("https://pаypal-verify.tk/login")


def test_canonicalize_leaves_an_ordinary_url_alone():
    url = "https://www.example.com/orders"
    assert canonicalize_url(url).rstrip("/") == url.rstrip("/")


def test_detects_ip_hosts_and_nonstandard_ports():
    f = url_features("http://192.168.4.9:8080/login")
    assert f["url_is_ip_host"] == 1.0
    assert f["url_nonstandard_port"] == 1.0


def test_detects_brand_squatting_and_typosquatting():
    squat = url_features("http://paypal-secure.tk/login")
    assert squat["url_brand_squat"] == 1.0
    assert squat["url_brand_impersonation"] == 1.0

    genuine = url_features("https://www.paypal.com/signin")
    assert genuine["url_official_brand_domain"] == 1.0
    assert genuine["url_brand_impersonation"] == 0.0


def test_detects_a_brand_in_a_subdomain_of_an_unrelated_domain():
    f = url_features("https://microsoft.com.security-update.cf/login")
    assert f["url_brand_mismatch"] == 1.0
    assert f["url_brand_impersonation"] == 1.0


def test_leet_substituted_brand_is_still_recognised():
    assert url_features("https://paypa1.com/login")["url_brand_impersonation"] == 1.0


def test_extracts_links_from_text_and_html_with_anchor_text():
    links = extract_links(
        "See http://plain.example/path",
        '<a href="http://real-target.tk/login">https://www.paypal.com/signin</a>',
    )
    hrefs = [h for h, _ in links]
    assert "http://real-target.tk/login" in hrefs
    assert any("plain.example" in h for h in hrefs)
    assert any("paypal.com" in label for _, label in links)


def test_link_text_href_mismatch_is_detected():
    links = extract_links("", '<a href="http://evil-domain.tk/x">https://www.paypal.com/signin</a>')
    assert aggregate_link_features(links)["link_text_shows_url_mismatch"] >= 1.0


def test_no_links_uses_neutral_defaults_not_zero_for_distance_features():
    """Zero means "exact brand match", so it is the wrong default for "absent"."""
    empty = aggregate_link_features([])
    assert empty["link_count"] == 0.0
    assert empty["url_lookalike_distance__max"] == 9.0
    assert empty["link_min_lookalike_distance"] == 9.0


def test_malformed_urls_do_not_raise():
    for bad in ["", "http://", "://nope", "ht tp://x", "https://[::1", "%%%"]:
        parse_url(bad)
        url_features(bad)


def test_feature_names_are_stable_and_unique():
    from phishguard.features.urls import LINK_AGG_NAMES, URL_FEATURE_NAMES

    assert len(set(URL_FEATURE_NAMES)) == len(URL_FEATURE_NAMES)
    assert len(set(LINK_AGG_NAMES)) == len(LINK_AGG_NAMES)
    produced = set(aggregate_link_features([("https://example.com/a", "")]))
    assert produced == set(LINK_AGG_NAMES)

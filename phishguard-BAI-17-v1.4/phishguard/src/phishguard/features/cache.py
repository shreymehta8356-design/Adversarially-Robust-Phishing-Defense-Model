"""A per-batch memo for feature extraction shared between ensemble members.

Two members -- the rule checklist and the engineered model -- both need the
email-level features and the extracted links of every message, and each used to
compute them independently. Profiling put the two at ~1.6 ms per message each,
which made them together the most expensive part of scoring a batch.

The memo is deliberately narrow:

* It is **scoped to one scoring call** (a context manager around
  ``_member_matrix``) and keyed by object identity within it, so it can never
  serve a stale result: the objects are alive for the duration of the call and
  the cache is discarded when it returns.
* It only covers calls that are **identical in both members**. URL aggregation
  is *not* shared, because the engineered member canonicalises URLs (D-URL) and
  the rule checklist does not; sharing it would silently change one of them.
* It returns **copies** of cached dicts, because one caller mutates the result
  (``feats.update(...)``) and must not pollute what the other reads.

A test pins that scores with and without the memo are bit-identical.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, TypeVar

T = TypeVar("T")

_CACHE: ContextVar[dict[tuple[str, int], Any] | None] = ContextVar("pg_feature_cache", default=None)


@contextmanager
def batch_cache() -> Iterator[None]:
    """Share feature extraction across members for the duration of one call."""
    if _CACHE.get() is not None:  # already inside a batch: reuse it
        yield
        return
    token = _CACHE.set({})
    try:
        yield
    finally:
        _CACHE.reset(token)


def _memo(kind: str, obj: Any, compute: Callable[[], T]) -> T:
    cache = _CACHE.get()
    if cache is None:
        return compute()
    key = (kind, id(obj))
    if key not in cache:
        cache[key] = compute()
    return cache[key]


def email_features_for(msg: Any) -> dict[str, float]:
    from phishguard.features.email import email_features

    return dict(_memo("email", msg, lambda: email_features(msg)))


def links_for(msg: Any) -> list[tuple[str, str]]:
    from phishguard.features.urls import extract_links

    return list(_memo("links", msg, lambda: extract_links(msg.body, msg.html_body)))

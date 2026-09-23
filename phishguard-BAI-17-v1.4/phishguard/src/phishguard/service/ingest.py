"""Bringing real mail into the system: file uploads and an IMAP inbox.

Two ways mail arrives here, both ending in the same place -- ``ScanService``,
so every message gets the same decision, audit record and review case as one
sent to ``POST /api/v1/scan``:

``parse_mail_bytes``   an ``.eml`` (one RFC 822 message) or an ``.mbox`` (many),
                       as uploaded from the console or the command line
``ImapWatcher``        polls a mailbox over IMAP for unseen messages and feeds
                       them in; state (the last UID seen) is kept on disk so a
                       restart does not re-score the whole inbox

Neither path fabricates sender history. A mailbox has none of the gateway's
behavioural context, so messages are assessed on email and URL evidence and the
verdict says so. The IMAP watcher only ever *reads*: it never moves, deletes or
replies to a message, and the credentials it uses should be an app password
scoped to reading.
"""

from __future__ import annotations

import imaplib
import json
import logging
import ssl
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from phishguard.data.loaders import LoadReport, load_mbox, message_from_rfc822_bytes
from phishguard.schemas import EmailMessage
from phishguard.service.contracts import ScanRequest
from phishguard.service.security import Principal

logger = logging.getLogger("phishguard.ingest")

MAX_UPLOAD_MESSAGES = 2_000


def _looks_like_mbox(data: bytes, filename: str) -> bool:
    if filename.lower().endswith(".mbox"):
        return True
    head = data.lstrip()[:5]
    return head == b"From "


def parse_mail_bytes(data: bytes, *, filename: str = "") -> list[EmailMessage]:
    """Parse an uploaded ``.eml`` or ``.mbox`` into messages.

    Anything that is not an mbox is treated as a single RFC 822 message, which
    is what Gmail's "Download message", Outlook's "Save as" and a raw paste of
    headers-plus-body all produce.
    """
    if not data.strip():
        raise ValueError("the upload is empty")
    if _looks_like_mbox(data, filename):
        # ``mailbox.mbox`` wants a path; the temporary file is deleted before
        # this returns, so nothing of the upload stays on disk.
        with tempfile.NamedTemporaryFile(suffix=".mbox", delete=False) as tmp:
            tmp.write(data)
            path = Path(tmp.name)
        try:
            messages, _ = load_mbox(
                path,
                label=0,
                source="upload",
                limit=MAX_UPLOAD_MESSAGES,
                report=LoadReport(),
            )
        finally:
            path.unlink(missing_ok=True)
        if not messages:
            raise ValueError("no readable messages in the mbox")
        return messages
    message = message_from_rfc822_bytes(data, source=f"upload:{filename or 'eml'}")
    if not (message.sender or message.subject):
        raise ValueError(
            "this does not look like a saved email: no From or Subject header was found"
        )
    return [message]


@dataclass(slots=True)
class IngestSummary:
    """What happened to a batch of ingested messages."""

    source: str
    received: int = 0
    allow: int = 0
    review: int = 0
    block: int = 0
    failed: int = 0
    seconds: float = 0.0
    results: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "received": self.received,
            "allow": self.allow,
            "review": self.review,
            "block": self.block,
            "failed": self.failed,
            "seconds": round(self.seconds, 3),
            "results": self.results,
        }


def ingest_messages(
    service: Any,
    messages: list[EmailMessage],
    *,
    source: str,
    principal: Principal | None = None,
    request_id: str | None = None,
) -> IngestSummary:
    """Run every message through the deployed decision path.

    REVIEW verdicts open cases exactly as an inline scan would, so an imported
    mailbox lands in the analyst queue rather than in a spreadsheet. Evidence
    is generated only for messages that will be looked at.
    """
    summary = IngestSummary(source=source, received=len(messages))
    started = time.perf_counter()
    for index, message in enumerate(messages):
        request = ScanRequest.from_message(message, client_reference=f"ingest:{source}"[:128])
        try:
            response = service.scan(
                request,
                principal=principal,
                request_id=request_id,
                explain=True,
                record=True,
                open_review_case=True,
            )
        except Exception:  # noqa: BLE001
            logger.exception("ingest: message %d from %s failed", index, source)
            summary.failed += 1
            continue
        band = response.band
        if band == "ALLOW":
            summary.allow += 1
        elif band == "REVIEW":
            summary.review += 1
        else:
            summary.block += 1
        summary.results.append(
            {
                "index": index,
                "subject": message.subject[:200],
                "sender": message.sender[:200],
                "band": band,
                "score": round(float(response.score), 4),
                "decision_id": response.decision_id,
                # The reason that supports the verdict: what alarmed the system
                # for a held or blocked message, what reassured it for a delivered one.
                "top_reason": next(
                    (
                        e.title
                        for e in (response.evidence or [])
                        if getattr(e, "direction", "")
                        == ("legitimate" if band == "ALLOW" else "phishing")
                        and getattr(e, "kind", "") != "feature"
                    ),
                    "",
                ),
            }
        )
    summary.seconds = time.perf_counter() - started
    return summary


# ------------------------------------------------------------------ IMAP


@dataclass(slots=True)
class ImapConfig:
    host: str
    user: str
    password: str
    folder: str = "INBOX"
    port: int = 993
    mark_seen: bool = False
    state_path: Path | None = None


class ImapWatcher:
    """Poll a mailbox for messages this system has not scored yet.

    Read-only by construction: the only IMAP commands issued are SELECT (in
    read-only mode unless ``mark_seen`` is on), UID SEARCH and UID FETCH. The
    last UID scored is persisted so a restart carries on where it stopped.
    """

    def __init__(self, config: ImapConfig, service: Any) -> None:
        self.config = config
        self.service = service
        self._last_uid = self._load_state()

    # -- state ------------------------------------------------------------
    def _load_state(self) -> int:
        path = self.config.state_path
        if path and path.exists():
            try:
                return int(json.loads(path.read_text(encoding="utf-8")).get("last_uid", 0))
            except (ValueError, OSError, AttributeError):
                return 0
        return 0

    def _save_state(self) -> None:
        path = self.config.state_path
        if not path:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "host": self.config.host,
                    "user": self.config.user,
                    "folder": self.config.folder,
                    "last_uid": self._last_uid,
                }
            ),
            encoding="utf-8",
        )

    # -- one poll ---------------------------------------------------------
    def poll(self, *, limit: int = 200) -> IngestSummary:
        """Fetch and score every message newer than the last one seen."""
        cfg = self.config
        context = ssl.create_default_context()
        client = imaplib.IMAP4_SSL(cfg.host, cfg.port, ssl_context=context)
        try:
            client.login(cfg.user, cfg.password)
            status, _ = client.select(cfg.folder, readonly=not cfg.mark_seen)
            if status != "OK":
                raise RuntimeError(f"could not open folder {cfg.folder!r}")
            criterion = f"UID {self._last_uid + 1}:*" if self._last_uid else "UNSEEN"
            status, data = client.uid("search", None, criterion)
            if status != "OK":
                raise RuntimeError("IMAP search failed")
            uids = [int(u) for u in (data[0] or b"").split() if int(u) > self._last_uid]
            uids = uids[:limit]
            messages: list[EmailMessage] = []
            fetched: list[int] = []
            for uid in uids:
                status, parts = client.uid("fetch", str(uid), "(BODY.PEEK[])")
                if status != "OK" or not parts or not isinstance(parts[0], tuple):
                    continue
                raw = parts[0][1]
                try:
                    messages.append(
                        message_from_rfc822_bytes(raw, source=f"imap:{cfg.folder}:{uid}")
                    )
                    fetched.append(uid)
                except Exception:  # noqa: BLE001
                    logger.warning("imap: could not parse uid %s", uid)
            summary = ingest_messages(self.service, messages, source=f"imap:{cfg.user}")
            if cfg.mark_seen and fetched:
                client.uid("store", ",".join(str(u) for u in fetched), "+FLAGS", "(\\Seen)")
            if fetched:
                self._last_uid = max(fetched)
                self._save_state()
            return summary
        finally:
            try:
                client.logout()
            except Exception:  # noqa: BLE001, S110 - logout failures are not actionable
                pass

    def run(self, *, interval: float = 60.0, once: bool = False) -> None:
        """Poll until interrupted, sleeping ``interval`` seconds between polls."""
        while True:
            try:
                summary = self.poll()
                logger.info(
                    "imap poll: %d new, allow %d review %d block %d",
                    summary.received,
                    summary.allow,
                    summary.review,
                    summary.block,
                )
                print(
                    f"{time.strftime('%H:%M:%S')}  {summary.received} new message(s): "
                    f"ALLOW {summary.allow}  REVIEW {summary.review}  BLOCK {summary.block}"
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("imap poll failed: %s", exc)
                print(f"{time.strftime('%H:%M:%S')}  poll failed: {exc}")
            if once:
                return
            time.sleep(max(5.0, interval))


__all__ = [
    "ImapConfig",
    "ImapWatcher",
    "IngestSummary",
    "ingest_messages",
    "parse_mail_bytes",
]

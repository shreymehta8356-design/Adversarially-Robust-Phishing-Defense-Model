"""Real mail coming in: .eml and .mbox uploads, and the IMAP watcher."""

from __future__ import annotations

import json
from pathlib import Path

from phishguard.service.ingest import (
    ImapConfig,
    ImapWatcher,
    ingest_messages,
    parse_mail_bytes,
)
from phishguard.service.security import Principal

PHISH_EML = b"""From: "PayPal" <service@paypa1-secure-login.com>
To: someone@example.com
Subject: Your account has been limited
Date: Mon, 21 Sep 2026 10:12:00 +0530
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypa1-secure-login.com; dkim=none; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

We noticed unusual activity. Verify your identity within 24 hours or your account will be suspended:
http://paypa1-secure-login.com/verify?id=88213
"""

HAM_EML = b"""From: "Priya Shah" <priya.shah@college.example>
To: someone@example.com
Subject: Lab timetable for next week
Date: Mon, 21 Sep 2026 09:00:00 +0530
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=college.example; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Hi all, the lab timetable for next week is on the notice board. The Tuesday slot moves to Thursday 2pm.
Thanks, Priya
"""


def _mbox(*emls: bytes) -> bytes:
    return b"".join(b"From MAILER-DAEMON Mon Sep 21 09:00:00 2026\n" + e + b"\n" for e in emls)


def test_an_eml_parses_into_one_message_without_invented_history():
    (msg,) = parse_mail_bytes(PHISH_EML, filename="a.eml")
    assert msg.subject == "Your account has been limited"
    assert "paypa1-secure-login.com" in msg.sender
    assert msg.auth.spf == "fail" and msg.auth.dmarc == "fail"
    assert msg.behavioral.available is False


def test_an_mbox_parses_into_many_messages_and_leaves_no_file_behind(tmp_path):
    before = set(Path(__import__("tempfile").gettempdir()).glob("*.mbox"))
    messages = parse_mail_bytes(_mbox(PHISH_EML, HAM_EML), filename="export.mbox")
    assert [m.subject for m in messages] == [
        "Your account has been limited",
        "Lab timetable for next week",
    ]
    after = set(Path(__import__("tempfile").gettempdir()).glob("*.mbox"))
    assert after == before


def test_an_mbox_is_recognised_by_content_when_the_name_gives_nothing_away():
    messages = parse_mail_bytes(_mbox(HAM_EML), filename="")
    assert len(messages) == 1


def test_garbage_is_refused_with_a_reason():
    for data in (b"", b"   \n", b"not a message at all"):
        try:
            parse_mail_bytes(data, filename="x.eml")
        except ValueError as exc:
            assert str(exc)
        else:
            raise AssertionError(f"accepted {data!r}")


def test_ingest_scores_audits_and_queues_like_an_inline_scan():
    from tests.helpers import scan_service

    service, store, _ = scan_service()
    messages = parse_mail_bytes(_mbox(PHISH_EML, HAM_EML), filename="export.mbox")
    before = store.count()
    summary = ingest_messages(
        service, messages, source="test", principal=Principal(key_id="key_t", role="analyst")
    )
    assert summary.received == 2 and summary.failed == 0
    assert summary.allow + summary.review + summary.block == 2
    bands = {r["subject"]: r["band"] for r in summary.results}
    assert bands["Your account has been limited"] == "BLOCK"
    assert bands["Lab timetable for next week"] != "BLOCK"
    assert all(r["decision_id"] for r in summary.results)
    assert store.count() == before + 2
    # The audit row carries the import as its client reference, never the text.
    rec = store.get_decision(summary.results[0]["decision_id"])
    assert rec["client_reference"].startswith("ingest:test")
    assert "paypa1-secure-login.com/verify" not in json.dumps(rec)


class _FakeImap:
    """Enough of imaplib.IMAP4_SSL for the watcher: read-only, UID-based."""

    instances: list[_FakeImap] = []

    def __init__(self, host, port, ssl_context=None):
        self.host, self.port = host, port
        self.commands: list[tuple] = []
        self.mail = {3: PHISH_EML, 5: HAM_EML}
        self.readonly = None
        _FakeImap.instances.append(self)

    def login(self, user, password):
        self.commands.append(("login", user))
        return "OK", []

    def select(self, folder, readonly=False):
        self.readonly = readonly
        self.commands.append(("select", folder, readonly))
        return "OK", [b"2"]

    def uid(self, cmd, *args):
        self.commands.append(("uid", cmd) + args)
        if cmd == "search":
            return "OK", [b" ".join(str(u).encode() for u in sorted(self.mail))]
        if cmd == "fetch":
            uid = int(args[0])
            return "OK", [(f"{uid} (BODY[] {{1}}".encode(), self.mail[uid]), b")"]
        if cmd == "store":
            return "OK", []
        raise AssertionError(cmd)

    def logout(self):
        self.commands.append(("logout",))
        return "BYE", []


def test_imap_watcher_reads_new_mail_only_and_never_writes(tmp_path, monkeypatch):
    import phishguard.service.ingest as ingest
    from tests.helpers import scan_service

    monkeypatch.setattr(ingest.imaplib, "IMAP4_SSL", _FakeImap)
    service, _, _ = scan_service()
    state = tmp_path / "imap-state.json"
    watcher = ImapWatcher(
        ImapConfig(host="imap.example", user="u@example", password="pw", state_path=state),
        service,
    )
    first = watcher.poll()
    assert first.received == 2
    client = _FakeImap.instances[-1]
    assert client.readonly is True
    assert not any(c[:2] == ("uid", "store") for c in client.commands)
    assert client.commands[-1] == ("logout",)
    assert json.loads(state.read_text())["last_uid"] == 5

    # Second poll: nothing newer than UID 5, so nothing is re-scored.
    second = watcher.poll()
    assert second.received == 0
    assert any(
        c[:3] == ("uid", "search", None) and "UID 6:*" in c[3]
        for c in _FakeImap.instances[-1].commands
    )

    # A fresh watcher picks up where the state file left off.
    again = ImapWatcher(watcher.config, service)
    assert again.poll().received == 0

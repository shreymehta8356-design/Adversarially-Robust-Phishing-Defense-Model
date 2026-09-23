"""Fixtures that reproduce the messiness of real public corpora.

Each builder writes files in the exact layout the public corpora use -- a Unix
mbox for Nazario, a maildir tree for Enron, a directory of numbered RFC-822
files with a ``cmds`` file for SpamAssassin, and CSVs with the label
conventions of the common Kaggle and UCI datasets -- so the loader tests
exercise the same code paths a real corpus would, without any real personal
data in the repository.
"""

from __future__ import annotations

import mailbox
import tempfile
from datetime import datetime, timezone
from email.message import EmailMessage as MimeMessage
from email.utils import format_datetime
from pathlib import Path

PHISH_BODIES = [
    "Your mailbox storage is full. Verify your account within 24 hours to avoid "
    "suspension: http://mailbox-verify-{i}.example/login",
    "We detected unusual sign-in activity. Confirm your identity now at "
    "http://secure-account-{i}.example/verify or your account will be closed.",
    "Your invoice {i} is overdue. Review the payment details here: "
    "http://billing-portal-{i}.example/invoice",
]

HAM_BODIES = [
    "Please find attached the revised schedule for the Q{i} gas contracts. Let me "
    "know if the volumes look right before Friday's call.",
    "The desk meeting has moved to 3pm. I have booked the conference room on 32.",
    "Thanks for sending the curve update. I have forwarded it to the risk group.",
]


def _mime(
    *,
    subject: str,
    sender: str,
    date: datetime,
    body: str | None = None,
    html: str | None = None,
    charset: str = "utf-8",
    auth: list[str] | None = None,
    received_spf: str | None = None,
    encode_subject: bool = False,
) -> MimeMessage:
    msg = MimeMessage()
    if encode_subject:
        # Real encoded subjects carry non-ASCII -- often a homoglyph, as here
        # (Cyrillic 'о' for Latin 'o'). A pure-ASCII subject would simply be
        # re-serialised as plain text and never exercise the decoding path.
        subject = subject.replace("o", "\u043e", 1)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = "recipient@corp.example"
    msg["Date"] = format_datetime(date)
    for header in auth or []:
        msg["Authentication-Results"] = header
    if received_spf:
        msg["Received-SPF"] = received_spf
    msg["Received"] = "from relay1.example by mx.corp.example"
    msg["Received"] = "from origin.example by relay1.example"
    if body is not None and html is not None:
        msg.set_content(body, charset=charset)
        msg.add_alternative(html, subtype="html")
    elif html is not None:
        msg.set_content(html, subtype="html")
    else:
        msg.set_content(body or "", charset=charset)
    return msg


def modern_phishing_mbox(directory: Path, n: int = 30, *, year: int = 2023) -> Path:
    """Nazario-style: recent phishing, auth verdicts, encoded subjects, HTML-only."""
    path = directory / f"phishing-{year}"
    box = mailbox.mbox(str(path))
    box.lock()
    try:
        for i in range(n):
            body = PHISH_BODIES[i % len(PHISH_BODIES)].format(i=i)
            kind = i % 3
            msg = _mime(
                subject=f"Action required: account notice {i}",
                sender=f"Security Team <security@notice-{i}.example>",
                date=datetime(year, 1 + i % 12, 1 + i % 27, 9, 0, tzinfo=timezone.utc),
                body=None if kind == 0 else body,
                html=f"<html><body><p>{body}</p><a href='http://x-{i}.example'>Verify</a></body></html>"
                if kind != 2
                else None,
                auth=[
                    f"mx.corp.example; spf=softfail smtp.mailfrom=notice-{i}.example; "
                    "dkim=none; dmarc=fail header.from=notice-{i}.example"
                ],
                encode_subject=(i % 2 == 0),
            )
            box.add(msg)
        box.flush()
    finally:
        box.unlock()
        box.close()
    return path


def old_ham_maildir(directory: Path, n: int = 30, *, year: int = 2001) -> Path:
    """Enron-style: legitimate mail from 2001, plain text, no auth headers."""
    root = directory / "enron" / "maildir" / "lay-k" / "inbox"
    root.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        msg = _mime(
            subject=f"Re: schedule {i}",
            sender=f"trader{i}@enron.example",
            date=datetime(year, 1 + i % 12, 1 + i % 27, 14, 30, tzinfo=timezone.utc),
            body=HAM_BODIES[i % len(HAM_BODIES)].format(i=i),
        )
        (root / f"{i + 1}.").write_bytes(msg.as_bytes())
    return directory / "enron" / "maildir"


def modern_ham_maildir(directory: Path, n: int = 30, *, year: int = 2023) -> Path:
    """Same-era legitimate mail, with the auth headers modern mail carries."""
    root = directory / "modern-ham"
    root.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        msg = _mime(
            subject=f"Re: schedule {i}",
            sender=f"colleague{i}@corp.example",
            date=datetime(year, 1 + i % 12, 1 + i % 27, 14, 30, tzinfo=timezone.utc),
            body=HAM_BODIES[i % len(HAM_BODIES)].format(i=i),
            auth=["mx.corp.example; spf=pass smtp.mailfrom=corp.example; dkim=pass; dmarc=pass"],
            encode_subject=(i % 2 == 0),
        )
        (root / f"{i:05d}.eml").write_bytes(msg.as_bytes())
    return root


def spamassassin_dir(directory: Path, n: int = 5) -> Path:
    """SpamAssassin layout: numbered files plus a ``cmds`` file that is not mail."""
    root = directory / "easy_ham"
    root.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        msg = _mime(
            subject=f"list post {i}",
            sender=f"user{i}@lists.example",
            date=datetime(2002, 8, 1 + i, tzinfo=timezone.utc),
            body=f"Posting number {i} to the list.",
        )
        (root / f"{i:05d}.{'a' * 32}").write_bytes(msg.as_bytes())
    (root / "cmds").write_text("mv 00001.abc 00001.def\nmv 00002.abc 00002.def\n")
    return root


def windows_1252_message() -> bytes:
    """A message whose declared charset is windows-1252, with curly quotes."""
    raw = (
        "From: sender@example.com\r\n"
        "To: you@example.com\r\n"
        "Subject: Quarterly report\r\n"
        "Date: Mon, 03 Jun 2002 10:00:00 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=windows-1252\r\n"
        "Content-Transfer-Encoding: 8bit\r\n\r\n"
    ).encode("ascii") + "We’ve attached the “final” numbers – thanks.\r\n".encode("windows-1252")
    return raw


def forged_auth_message() -> bytes:
    """Two Authentication-Results headers: the topmost (receiver's) says fail,
    a lower one -- which travelled with the message and is attacker-controlled --
    claims pass."""
    return (
        "Authentication-Results: mx.corp.example; spf=fail; dkim=fail; dmarc=fail\r\n"
        "Authentication-Results: fake.example; spf=pass; dkim=pass; dmarc=pass\r\n"
        "From: PayPal <service@paypal.example>\r\n"
        "To: you@example.com\r\n"
        "Subject: Verify now\r\n"
        "Date: Tue, 04 Jun 2024 10:00:00 +0000\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n\r\n"
        "Verify your account at http://paypal-verify.example/login\r\n"
    ).encode("ascii")


def csv_file(directory: Path, name: str, rows: list[dict[str, str]]) -> Path:
    import csv

    path = directory / name
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return path


def tmpdir() -> Path:
    return Path(tempfile.mkdtemp(prefix="pg-realmail-"))

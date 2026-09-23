"""Fetching public corpora: terms first, provenance always, archives distrusted."""

from __future__ import annotations

import io
import json
import tarfile
import tempfile
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from phishguard.data import fetch as F


def _tarball(path: Path, members: dict[str, bytes], *, evil: str | None = None) -> Path:
    with tarfile.open(path, "w:bz2") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        if evil == "link":
            info = tarfile.TarInfo("easy_ham/link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tar.addfile(info)
    return path


def test_nothing_is_downloaded_until_the_terms_are_accepted():
    d = Path(tempfile.mkdtemp(prefix="pg-fetch-"))
    try:
        F.fetch(["spamassassin-easy-ham"], d)
    except F.TermsNotAccepted as exc:
        assert "never sent into a live mail system" in str(exc)
    else:
        raise AssertionError("downloaded without accepting the terms")
    assert list(d.iterdir()) == []


def test_every_listed_source_uses_https_and_names_its_terms():
    for src in F.SOURCES.values():
        assert src.url.startswith("https://")
        assert src.label in {"phish", "ham"} and len(src.terms) > 80


def test_archives_that_escape_the_folder_or_contain_links_are_refused():
    d = Path(tempfile.mkdtemp(prefix="pg-fetch-"))
    for bad, evil in (
        ({"../../outside.txt": b"x"}, None),
        ({"/abs/path.txt": b"x"}, None),
        ({"easy_ham/00001.eml": b"ok"}, "link"),
    ):
        archive = _tarball(d / "bad.tar.bz2", bad, evil=evil)
        try:
            F.safe_extract(archive, d / "out")
        except F.UnsafeArchive:
            pass
        else:
            raise AssertionError(f"unsafe archive accepted: {bad} {evil}")
    assert not (d.parent / "outside.txt").exists()


def test_a_download_is_extracted_and_its_provenance_recorded():
    served = Path(tempfile.mkdtemp(prefix="pg-serve-"))
    _tarball(
        served / "20030228_easy_ham.tar.bz2",
        {
            "easy_ham/00001.abc": b"From: a@b.example\r\nSubject: hi\r\n\r\nhello\r\n",
            "easy_ham/cmds": b"mv a b\n",
        },
    )

    class _Quiet(SimpleHTTPRequestHandler):
        def log_message(self, *args):  # keep test output clean
            pass

    handler = partial(_Quiet, directory=str(served))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        src = F.Source(
            "test-ham",
            f"http://127.0.0.1:{port}/20030228_easy_ham.tar.bz2",
            "tar.bz2",
            "ham",
            "2003",
            "Test terms " * 10,
            "easy_ham",
        )
        data = Path(tempfile.mkdtemp(prefix="pg-data-"))
        records = F.fetch(["test-ham"], data, accept_terms=True, sources={"test-ham": src})
    finally:
        server.shutdown()
    assert (data / "easy_ham" / "00001.abc").read_bytes().startswith(b"From:")
    assert not (data / "20030228_easy_ham.tar.bz2").exists(), (
        "the archive is removed after extraction"
    )
    provenance = json.loads((data / "PROVENANCE.json").read_text(encoding="utf-8"))
    assert provenance[0]["sha256"] == records[0]["sha256"] and len(records[0]["sha256"]) == 64
    assert provenance[0]["terms_acknowledged"] is True
    assert records[0]["data_source_spec"].endswith("easy_ham#ham")


def test_plain_http_is_refused_except_on_this_machine():
    for url in ("http://example.com/x", "ftp://example.com/x", "file:///etc/passwd"):
        try:
            F._check_url(url)
        except ValueError:
            continue
        raise AssertionError(f"accepted {url}")
    F._check_url("http://127.0.0.1:8000/x")
    F._check_url("https://monkey.org/~jose/phishing/phishing-2024")

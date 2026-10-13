"""Crash log: private, size-capped, and never able to raise a second error."""
from __future__ import annotations

import stat
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuiteUI"))

from linuxguardian_ui import crashlog  # noqa: E402


def boom():
    raise RuntimeError("tab exploded /home/me/thing")


def test_record_writes_a_private_entry_with_the_traceback(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path))
    try:
        boom()
    except RuntimeError as exc:
        summary = crashlog.record("building the Test tab", exc)
    assert summary == "RuntimeError: tab exploded /home/me/thing"
    p = tmp_path / "logs" / "app-errors.log"
    text = p.read_text()
    assert "building the Test tab" in text and "in boom" in text and "RuntimeError" in text
    assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_entries_append_and_the_log_is_rotated_by_size(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path))
    monkeypatch.setattr(crashlog, "MAX_BYTES", 200)
    for i in range(10):
        crashlog.record(f"call {i}", ValueError("x" * 50))
    assert (tmp_path / "logs" / "app-errors.log.1").exists()
    assert (tmp_path / "logs" / "app-errors.log").stat().st_size < 2000


def test_logging_can_never_raise(tmp_path, monkeypatch):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setenv("LG_HOME", str(blocker))                         # the log folder can't even be created
    assert crashlog.record("x", ValueError("y")) == "error"


def test_install_routes_main_and_thread_exceptions_to_the_log(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path))
    seen = []
    monkeypatch.setattr(sys, "excepthook", lambda *a: seen.append(a))
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)
    crashlog.install()
    try:
        raise KeyError("main thread")
    except KeyError:
        sys.excepthook(*sys.exc_info())
    t = threading.Thread(target=lambda: (_ for _ in ()).throw(ValueError("worker thread")), name="w1")
    t.start()
    t.join()
    text = (tmp_path / "logs" / "app-errors.log").read_text()
    assert "main thread" in text and "worker thread" in text and "thread w1" in text
    assert seen and seen[0][0] is KeyError                                # the previous handler still runs

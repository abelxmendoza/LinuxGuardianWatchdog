"""Keep a private record of crashes, so a broken tab or callback is explained and logged instead of just vanishing.

Nothing here can itself raise into the app: logging a crash must never cause a second one.
"""
from __future__ import annotations

import os
import sys
import threading
import time
import traceback
from pathlib import Path

MAX_BYTES = 1024 * 1024


def log_path() -> Path:
    return Path(os.environ.get("LG_HOME", str(Path.home() / ".linuxguardian"))) / "logs" / "app-errors.log"


def record(where: str, exc: BaseException | None = None) -> str:
    """Append one entry (private, size-capped). Returns the one-line summary. Never raises."""
    try:
        exc = exc or sys.exc_info()[1]
        text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)) if exc else "(no exception)\n"
        summary = f"{type(exc).__name__}: {exc}" if exc else "unknown error"
        p = log_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.is_file() and p.stat().st_size > MAX_BYTES:
            p.replace(p.with_name(p.name + ".1"))
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(f"=== {time.strftime('%Y-%m-%d %H:%M:%S')} in {where}\n{text}\n")
        return summary
    except Exception:  # noqa: BLE001 - see module docstring
        return "error"


def install() -> None:
    """Route uncaught exceptions (main thread, worker threads, GTK callbacks) into the log, then on to the default handler."""
    previous = sys.excepthook

    def hook(etype, value, tb):
        record("uncaught exception", value)
        previous(etype, value, tb)

    sys.excepthook = hook

    def thread_hook(args):
        record(f"thread {getattr(args.thread, 'name', '?')}", args.exc_value)

    threading.excepthook = thread_hook

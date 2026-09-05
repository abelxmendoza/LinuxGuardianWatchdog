"""Thin subprocess wrapper around LinuxGuardianSuite/*.sh.

Mirrors the macOS original's approach: the GUI never re-implements the
security logic, it just shells out to the scripts and streams the output.
"""
from __future__ import annotations

import codecs
import os
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parents[2] / "LinuxGuardianSuite"
_PROGRESS_PREFIX = "LG_PROGRESS"
_PROGRESS_UI_INTERVAL = 0.15


def script_path(name: str) -> Path:
    path = SUITE_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Script not found: {path}")
    return path


def _script_cmd(name: str, args: tuple[str, ...] | list[str]) -> list[str]:
    cmd = [str(script_path(name)), *args]
    stdbuf = shutil.which("stdbuf")
    if stdbuf:
        # Bash is fully buffered when piped; force line-buffered so the GUI
        # sees heartbeats immediately instead of after a 4KB fill.
        cmd = [stdbuf, "-oL", "-eL", *cmd]
    return cmd


def run_sync(name: str, *args: str, timeout: float = 15.0) -> tuple[int, list[str]]:
    """Run a suite script to completion and return (exit_code, stdout_lines)."""
    proc = subprocess.run(
        _script_cmd(name, args),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout.splitlines()


def _iter_process_lines(proc: subprocess.Popen[bytes]) -> Iterator[str]:
    """Yield stdout lines, treating CR progress redraws as line breaks."""
    assert proc.stdout is not None
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    buf = ""
    while True:
        chunk = proc.stdout.read(256)
        if not chunk:
            buf += decoder.decode(b"", final=True)
            break
        buf += decoder.decode(chunk)
        buf = buf.replace("\r\n", "\n").replace("\r", "\n")
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            yield line
    if buf:
        yield buf


def run_streaming(name: str, *args: str) -> Iterator[str]:
    """Run a suite script and yield its combined stdout/stderr line by line."""
    proc = subprocess.Popen(
        _script_cmd(name, args),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    try:
        yield from _iter_process_lines(proc)
    finally:
        proc.wait()


def run_streaming_async(
    name: str,
    args: list[str],
    on_line: Callable[[str], None],
    on_done: Callable[[int], None],
) -> Callable[[], None]:
    """GLib-friendly variant: pushes each line to `on_line` via GLib.idle_add.

    Intended to be called from a background thread so the GTK main loop is
    never blocked by a long-running scan. Returns a cancel callback that
    SIGTERMs the script process group (so child scanners die too).
    """
    from gi.repository import GLib

    cancel_event = threading.Event()
    holder: dict[str, subprocess.Popen[bytes] | None] = {"proc": None}
    lock = threading.Lock()

    def cancel() -> None:
        cancel_event.set()
        with lock:
            proc = holder["proc"]
        if proc is None or proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                proc.kill()

    def worker() -> None:
        proc: subprocess.Popen[bytes] | None = None
        try:
            proc = subprocess.Popen(
                _script_cmd(name, args),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                start_new_session=True,
            )
            with lock:
                holder["proc"] = proc
            last_progress = 0.0
            pending_progress: str | None = None
            for line in _iter_process_lines(proc):
                if cancel_event.is_set():
                    break
                if line.startswith(_PROGRESS_PREFIX):
                    pending_progress = line
                    now = time.monotonic()
                    if now - last_progress < _PROGRESS_UI_INTERVAL:
                        continue
                    last_progress = now
                    pending_progress = None
                GLib.idle_add(on_line, line)
            if pending_progress is not None:
                GLib.idle_add(on_line, pending_progress)
            proc.wait()
            code = 130 if cancel_event.is_set() else (proc.returncode or 0)
            GLib.idle_add(on_done, code)
        except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
            GLib.idle_add(on_line, f"[error] {exc}")
            GLib.idle_add(on_done, 1)
        finally:
            if proc is not None and proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    proc.kill()

    threading.Thread(target=worker, daemon=True).start()
    return cancel


def run_sync_async(
    name: str,
    args: list[str],
    on_done: Callable[[int, list[str]], None],
    timeout: float = 15.0,
) -> None:
    """Background-thread variant of `run_sync`; calls `on_done` on the main loop."""
    import threading

    from gi.repository import GLib

    def worker() -> None:
        try:
            code, lines = run_sync(name, *args, timeout=timeout)
        except subprocess.TimeoutExpired:
            GLib.idle_add(on_done, 1, [f"[error] timed out after {timeout:.0f}s"])
            return
        except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
            GLib.idle_add(on_done, 1, [f"[error] {exc}"])
            return
        GLib.idle_add(on_done, code, lines)

    threading.Thread(target=worker, daemon=True).start()

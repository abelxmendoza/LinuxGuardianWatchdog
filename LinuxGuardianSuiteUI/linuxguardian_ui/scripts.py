"""Thin subprocess wrapper around LinuxGuardianSuite/*.sh.

Mirrors the macOS original's approach: the GUI never re-implements the
security logic, it just shells out to the scripts and streams the output.
"""
from __future__ import annotations

import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parents[2] / "LinuxGuardianSuite"


def script_path(name: str) -> Path:
    path = SUITE_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Script not found: {path}")
    return path


def run_streaming(name: str, *args: str) -> Iterator[str]:
    """Run a suite script and yield its combined stdout/stderr line by line."""
    proc = subprocess.Popen(
        [str(script_path(name)), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        yield line.rstrip("\n")
    proc.wait()


def run_streaming_async(
    name: str,
    args: list[str],
    on_line: Callable[[str], None],
    on_done: Callable[[int], None],
) -> None:
    """GLib-friendly variant: pushes each line to `on_line` via GLib.idle_add.

    Intended to be called from a background thread so the GTK main loop is
    never blocked by a long-running scan.
    """
    import threading

    from gi.repository import GLib

    def worker() -> None:
        try:
            for line in run_streaming(name, *args):
                GLib.idle_add(on_line, line)
            GLib.idle_add(on_done, 0)
        except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
            GLib.idle_add(on_line, f"[error] {exc}")
            GLib.idle_add(on_done, 1)

    threading.Thread(target=worker, daemon=True).start()

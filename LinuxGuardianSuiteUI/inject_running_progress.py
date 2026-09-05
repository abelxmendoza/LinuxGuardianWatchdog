#!/usr/bin/env python3
"""Write live status lines into the already-open Watchdog output pane.

The old GUI is blocked on a pipe from linux_guardian.sh. Opening that
process's stdout fd and writing complete lines makes them appear in the
text view without restarting (which would kill the scan).
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from linuxguardian_ui.live_scan import find_running_scan, human_bytes, snapshot
from linuxguardian_ui.progress import format_duration

PIPE_CANDIDATES = (
    # bash / tee stdout — pipe:[50256], the fd Python is reading
)


def _pipe_path(scan) -> str | None:
    for pid in (scan.script_pid, scan.pid):
        if not pid:
            continue
        path = f"/proc/{pid}/fd/1"
        try:
            target = os.readlink(path)
        except OSError:
            continue
        if target.startswith("pipe:"):
            return path
    return None


def main() -> int:
    scan = find_running_scan()
    if scan is None:
        print("no running scan", file=sys.stderr)
        return 1
    pipe = _pipe_path(scan)
    if pipe is None:
        print("could not find scan stdout pipe", file=sys.stderr)
        return 1
    fd = os.open(pipe, os.O_WRONLY | os.O_NONBLOCK)
    last = ""
    try:
        intro = (
            "[INFO] Live progress attached. This scan was already running; "
            "status will update every 2s so you can see it is not frozen.\n"
        )
        os.write(fd, intro.encode())
        while True:
            snap = snapshot(scan)
            if not snap.alive:
                os.write(
                    fd,
                    b"[INFO] Scanner process ended. If ClamAV finished cleanly, "
                    b"rkhunter may still run.\n",
                )
                return 0
            current = snap.current or snap.target
            line = (
                f"[INFO] still running — {format_duration(snap.elapsed_sec)} elapsed, "
                f"{human_bytes(snap.bytes_read)} read, CPU {snap.cpu_pct}; "
                f"current: {current}\n"
            )
            if line != last:
                os.write(fd, line.encode())
                last = line
            time.sleep(2)
    except BrokenPipeError:
        return 0
    except OSError as exc:
        print(f"inject failed: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())

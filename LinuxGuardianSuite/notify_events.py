#!/usr/bin/env python3
"""Desktop notifications for NEW security findings, and nothing else.

Looks at the event files written since the last time it ran and tells you about the ones that
need attention (warning or critical, not "resolved"). The first run only sets a starting point,
so installing this never replays your history as a burst of popups. Several new findings are
rolled into ONE notification. Because detectors only write an event when a finding is new
(audit_events.py, linux_exposure.sh --record), a long-standing finding doesn't nag.

  notify_events.py --send        notify about new findings since the last run
  notify_events.py --test        send a test notification
  notify_events.py --status | --enable | --disable

Never takes any action on the system: it only calls `notify-send`.
Test hooks: LG_HOME, LG_NOTIFY_CMD (default: notify-send).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

from events import lg_home  # noqa: E402
from timeline import RANK, load_entries  # noqa: E402

APP_NAME = "LinuxGuardian"
ICON = "linuxguardian-watchdog"


def _state_dir() -> Path:
    return lg_home() / "state"


def _marker() -> Path:
    return _state_dir() / "notify.json"


def _disabled_flag() -> Path:
    return _state_dir() / "notify_disabled"


def is_enabled() -> bool:
    return not _disabled_flag().exists()


def set_enabled(enabled: bool) -> None:
    _state_dir().mkdir(parents=True, exist_ok=True)
    if enabled:
        _disabled_flag().unlink(missing_ok=True)
    else:
        _disabled_flag().write_text("")


def _read_watermark() -> float | None:
    try:
        return float(json.loads(_marker().read_text())["last_epoch"])
    except (OSError, ValueError, KeyError, json.JSONDecodeError, TypeError):
        return None


def _write_watermark(epoch: float) -> None:
    _state_dir().mkdir(parents=True, exist_ok=True)
    tmp = _marker().with_suffix(".tmp")
    tmp.write_text(json.dumps({"last_epoch": epoch}))
    tmp.replace(_marker())


def _notify_cmd() -> str | None:
    return shutil.which(os.environ.get("LG_NOTIFY_CMD", "notify-send"))


def send_notification(title: str, body: str, *, critical: bool = False) -> bool:
    cmd = _notify_cmd()
    if not cmd:
        return False
    args = [cmd, "-a", APP_NAME, "-i", ICON, "-u", "critical" if critical else "normal", title, body]
    try:
        return subprocess.run(args, timeout=10, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def compose(entries: list) -> tuple[str, str, bool]:
    """(title, body, critical?) for a non-empty list of new entries, worst first."""
    entries = sorted(entries, key=lambda e: (-RANK[e.severity], -e.last_ts))
    critical = entries[0].severity == "critical"
    if len(entries) == 1:
        e = entries[0]
        return f"{APP_NAME}: {'critical finding' if critical else 'new warning'}", e.message, critical
    bullets = "\n".join(f"• {e.message}" for e in entries[:4])
    more = f"\n…and {len(entries) - 4} more" if len(entries) > 4 else ""
    return f"{APP_NAME}: {len(entries)} new findings", bullets + more, critical


def run_send(now: float | None = None) -> int:
    """Returns how many findings were announced (0 when disabled, first run, or nothing new)."""
    now = time.time() if now is None else now
    if not is_enabled():
        _write_watermark(now)       # findings from the off period are in the Timeline, not replayed later
        return 0
    last = _read_watermark()
    if last is None:
        _write_watermark(now)       # first run: start from now, don't replay history
        return 0
    fresh = [
        e for e in load_entries()
        if e.last_ts > last and e.status != "resolved" and RANK[e.severity] >= RANK["warning"]
    ]
    _write_watermark(now)
    if not fresh:
        return 0
    title, body, critical = compose(fresh)
    return len(fresh) if send_notification(title, body, critical=critical) else 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group(required=True)
    for flag in ("send", "test", "status", "enable", "disable"):
        g.add_argument(f"--{flag}", action="store_true")
    a = p.parse_args()
    if a.send:
        run_send()
    elif a.test:
        ok = send_notification(f"{APP_NAME}: test", "Notifications are working. You'll see new security findings here.")
        print("sent" if ok else "could not send (is notify-send installed and a desktop session running?)")
        return 0 if ok else 1
    elif a.status:
        print("on" if is_enabled() else "off")
    elif a.enable:
        set_enabled(True)
    elif a.disable:
        set_enabled(False)
    return 0


if __name__ == "__main__":
    sys.exit(main())

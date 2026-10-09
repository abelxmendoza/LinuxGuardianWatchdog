#!/usr/bin/env python3
"""How much can you trust a scan result right now?  (read-only, no root)

A "Clean" verdict is only as good as the virus definitions behind it and as
real as the scanners that actually ran. This reports, without needing root:

  * ClamAV definitions: how old the newest signature database is
  * the freshclam updater service: installed / enabled / running
  * rkhunter: installed? baseline database present and how old? and whether
    the last saved scan's rootkit check actually ran

Output: JSON (default), --text, or --summary (one key=value line).

Test hooks: LG_CLAMAV_DIR, LG_RKHUNTER_DB, LG_HOME.
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

from scan_store import rootkit_check_status  # noqa: E402

DAY = 86400
# ClamAV publishes new signatures several times a day, so even a couple of
# days without an update is worth a nudge; a week is genuinely stale.
FRESH_DAYS = 2
STALE_DAYS = 7


def _run(cmd: list[str], timeout: float = 10) -> str:
    env = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def fmt_age(seconds: float | None) -> str:
    if seconds is None:
        return "unknown"
    if seconds < 3600:
        return f"{int(seconds // 60)} minutes ago" if seconds >= 120 else "just now"
    if seconds < DAY:
        return f"{int(seconds // 3600)} hours ago"
    days = int(seconds // DAY)
    if days < 60:
        return f"{days} day{'s' if days != 1 else ''} ago"
    return f"{days // 30} months ago"


def definitions_status(now: float | None = None) -> dict:
    """Age of the newest ClamAV signature database.

    daily.* is what changes (several times a day); main.* and bytecode.* only
    change on big releases, so they would make an old install look fresh or
    stale for the wrong reason. Falls back to the newest of any if daily is absent.
    """
    now = time.time() if now is None else now
    directory = Path(os.environ.get("LG_CLAMAV_DIR", "/var/lib/clamav"))
    daily = [p for p in directory.glob("daily.c[lv]d") if p.is_file()]
    anyfiles = [p for p in directory.glob("*.c[lv]d") if p.is_file()]
    chosen = max(daily or anyfiles, key=lambda p: p.stat().st_mtime, default=None)
    if chosen is None:
        return {"present": False, "level": "missing", "age_sec": None, "file": None, "newest_epoch": None}
    mtime = chosen.stat().st_mtime
    age = max(0.0, now - mtime)
    level = "ok" if age <= FRESH_DAYS * DAY else "warning" if age <= STALE_DAYS * DAY else "critical"
    return {"present": True, "level": level, "age_sec": int(age), "file": chosen.name, "newest_epoch": int(mtime)}


def freshclam_service() -> dict:
    enabled = _run(["systemctl", "is-enabled", "clamav-freshclam"]).strip()
    installed = enabled in {"enabled", "disabled", "static", "masked", "indirect", "alias", "enabled-runtime"}
    active = _run(["systemctl", "is-active", "clamav-freshclam"]).strip() == "active"
    return {"installed": installed, "enabled": enabled == "enabled", "active": active, "unit_state": enabled}


def last_scan() -> dict | None:
    path = Path(os.environ.get("LG_HOME", str(Path.home() / ".linuxguardian"))) / "scans" / "last.json"
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def rkhunter_status(now: float | None = None) -> dict:
    now = time.time() if now is None else now
    installed = shutil.which("rkhunter") is not None
    db = Path(os.environ.get("LG_RKHUNTER_DB", "/var/lib/rkhunter/db/rkhunter.dat"))
    baseline_epoch: int | None = None
    try:
        # stat() only needs the directory to be searchable, even though the file itself is root-only.
        baseline_epoch = int(db.stat().st_mtime)
    except OSError:
        pass
    scan = last_scan()
    last_check = None
    if scan:
        last_check = scan.get("rootkit_check")
        if last_check is None:
            report = scan.get("rk_report")
            last_check = rootkit_check_status(Path(report)) if report else "not_run"
    return {
        "installed": installed,
        "baseline_present": baseline_epoch is not None,
        "baseline_epoch": baseline_epoch,
        "baseline_age_sec": None if baseline_epoch is None else max(0, int(now - baseline_epoch)),
        "last_check": last_check,
    }


def collect(now: float | None = None) -> dict:
    return {
        "definitions": definitions_status(now),
        "freshclam": freshclam_service(),
        "rkhunter": rkhunter_status(now),
    }


ENABLE_UPDATER_CMD = "sudo systemctl enable --now clamav-freshclam"

_LAST_CHECK_TEXT = {
    "ran": "last check ran",
    "needs_root": "last check skipped (needs root)",
    "cancelled": "last check cancelled",
    "not_run": "last check did not run",
    None: "never checked",
}


def describe(health: dict) -> list[dict]:
    """The same facts as rows a UI can colour: {key, label, text, level, command?}.

    level is ok | warning | critical. The UI shows `command` as copyable text and never runs it:
    enabling a system service is the user's call.
    """
    d, f, r = health["definitions"], health["freshclam"], health["rkhunter"]
    rows: list[dict] = []
    if d["present"]:
        rows.append({"key": "definitions", "label": "Virus definitions",
                     "text": f"Updated {fmt_age(d['age_sec'])}", "level": d["level"]})
    else:
        rows.append({"key": "definitions", "label": "Virus definitions",
                     "text": "Not found: ClamAV has nothing to scan with", "level": "critical"})
    if f["active"]:
        rows.append({"key": "auto_update", "label": "Automatic updates", "text": "On", "level": "ok"})
    elif not f["installed"]:
        rows.append({"key": "auto_update", "label": "Automatic updates",
                     "text": "Updater service not installed", "level": "warning"})
    else:
        rows.append({"key": "auto_update", "label": "Automatic updates",
                     "text": "Off: definitions only change when you press Update Definitions",
                     "level": "warning", "command": ENABLE_UPDATER_CMD})
    if not r["installed"]:
        rows.append({"key": "rootkit", "label": "Rootkit scanner", "text": "rkhunter is not installed", "level": "warning"})
    else:
        base = (f"baseline from {fmt_age(r['baseline_age_sec'])}" if r["baseline_present"]
                else "no baseline database found")
        last = _LAST_CHECK_TEXT.get(r["last_check"], str(r["last_check"]))
        rows.append({"key": "rootkit", "label": "Rootkit scanner", "text": f"{base}, {last}",
                     "level": "ok" if r["last_check"] == "ran" else "warning"})
    return rows


def render_text(health: dict) -> str:
    lines = []
    for row in describe(health):
        line = f"{row['label']}: {row['text']}"
        if row.get("command"):
            line += f". Turn on with: {row['command']}"
        lines.append(line)
    return "\n".join(lines)


def render_summary(health: dict) -> str:
    d, f, r = health["definitions"], health["freshclam"], health["rkhunter"]
    return " ".join(
        [
            f"definitions={d['level']}",
            f"definitions_age_sec={d['age_sec'] if d['age_sec'] is not None else '-'}",
            f"auto_update={'on' if f['active'] else 'off'}",
            f"rkhunter={'installed' if r['installed'] else 'missing'}",
            f"rootkit_last={r['last_check'] or 'never'}",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--json", action="store_true", help="JSON (the default)")
    parser.add_argument("--text", action="store_true")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()
    health = collect()
    if args.summary:
        print(render_summary(health))
    elif args.text:
        print(render_text(health))
    else:
        print(json.dumps(health))
    return 0


if __name__ == "__main__":
    sys.exit(main())

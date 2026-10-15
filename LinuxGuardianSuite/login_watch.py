#!/usr/bin/env python3
"""Login watch: how long the desktop takes to appear after you log in, and what LinuxGuardian changed before it got slow.

Security changes must never quietly break the computer. A firewall or kernel setting can make the desktop sit at a
black screen at login (on 2026-10-15 a loopback-IPv6 setting made a login helper wait ~130 s for ::1). So:

  * every login is timed from the journal: "Xsession: Beginning session setup" to the next "Running GNOME Shell";
    normal is a few seconds, anything over 30 s is reported
  * every system change LinuxGuardian makes (hardening fixes, firewall changes) is written to a ledger first, with
    how long the last login took and the command that undoes it
  * a slow login names the changes made since the last normal login, with their undo commands

Read-only, no root (the journal is readable for the 'adm' group).

  login_watch.py --check [--json]                       recent logins and how long each took
  login_watch.py --mark-change WHAT --undo COMMAND      record a system change about to be made (scripts call this)

Test hooks: LG_HOME; journalctl is found on PATH; LG_LOGIN_JOURNAL (a file with `journalctl -o short-unix` lines instead).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

from events import lg_home  # noqa: E402

SLOW_SECONDS = 30.0
NORMAL_SECONDS = 10.0
KEEP_LOGINS = 30
MAX_PAIR_SECONDS = 900.0           # a shell later than this belongs to another login (or another boot), not to this setup
KEEP_CHANGES = 50
_SETUP = "Beginning session setup"
_SHELL = "Running GNOME Shell"
_LINE = re.compile(r"^(\d+(?:\.\d+)?)\s+\S+\s+(.*)$")


def ledger_path() -> Path:
    return lg_home() / "state" / "system_changes.json"


def load_ledger() -> list[dict]:
    try:
        data = json.loads(ledger_path().read_text())
    except (OSError, ValueError):
        return []
    return data if isinstance(data, list) else []


def _journal_text() -> str:
    fake = os.environ.get("LG_LOGIN_JOURNAL")
    if fake:
        try:
            return Path(fake).read_text(errors="replace")
        except OSError:
            return ""
    if not shutil.which("journalctl"):
        return ""
    try:
        return subprocess.run(["journalctl", "-o", "short-unix", "--no-pager", "-q", "--since", "-3d", "--grep", f"{_SETUP}|{_SHELL}"],
                              capture_output=True, text=True, timeout=30, check=False).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def parse_logins(text: str) -> list[dict]:
    """[{start, seconds}] for each login: session setup, then the first GNOME Shell that starts after it.

    The login screen runs its own GNOME Shell before you log in; that one comes before the setup line, so it is never paired.
    A setup with no shell within 15 minutes (a login that never finished, or the laptop was switched off) gets seconds=None.
    """
    events = []
    for raw in text.splitlines():
        m = _LINE.match(raw.strip())
        if not m:
            continue
        ts, msg = float(m.group(1)), m.group(2)
        if _SETUP in msg:
            events.append(("setup", ts))
        elif _SHELL in msg:
            events.append(("shell", ts))
    events.sort(key=lambda e: e[1])
    logins = []
    pending: float | None = None
    for kind, ts in events:
        if kind == "setup":
            if pending is not None:
                logins.append({"start": pending, "seconds": None})
            pending = ts
        elif pending is not None:
            gap = ts - pending
            logins.append({"start": pending, "seconds": round(gap, 1) if gap <= MAX_PAIR_SECONDS else None})
            pending = None
    if pending is not None:
        logins.append({"start": pending, "seconds": None})
    return logins


def last_login_seconds() -> float | None:
    done = [entry for entry in parse_logins(_journal_text()) if entry["seconds"] is not None]
    return done[-1]["seconds"] if done else None


def mark_change(what: str, undo: str, when: float | None = None) -> dict:
    """Write a change to the ledger BEFORE it is made: the timing of the login before it is the baseline."""
    entry = {"time": when or time.time(), "what": what[:200], "undo": undo[:300], "login_before": last_login_seconds()}
    ledger = (load_ledger() + [entry])[-KEEP_CHANGES:]
    path = ledger_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(ledger, indent=1))
    tmp.replace(path)
    return entry


def _hardening_changes() -> list[dict]:
    """Hardening fixes still applied (hardening_undo.json): they predate the ledger, so they are read from there too."""
    try:
        data = json.loads((lg_home() / "state" / "hardening_undo.json").read_text())
    except (OSError, ValueError):
        return []
    root = {"sysctl", "ufw_ipv6", "ufw_logging", "lo_ipv6"}
    out = []
    for fid, rec in data.items() if isinstance(data, dict) else ():
        if isinstance(rec, dict) and isinstance(rec.get("applied"), (int, float)):
            cmd = f"{SUITE_DIR}/linux_hardening.sh --undo {fid}" if fid in root else f"{SUITE_DIR}/hardening.py --undo {fid}"
            out.append({"time": float(rec["applied"]), "what": f"Hardening applied: {fid}", "undo": cmd})
    return out


def all_changes() -> list[dict]:
    seen = {(round(c.get("time", 0)), c.get("what")) for c in load_ledger()}
    extra = [c for c in _hardening_changes() if not any(abs(c["time"] - t) < 120 and w == c["what"] for t, w in seen)]
    return sorted(load_ledger() + extra, key=lambda c: c.get("time", 0))


def changes_between(after: float, before: float) -> list[dict]:
    return [c for c in all_changes() if after < c.get("time", 0) <= before]


def _ranked(changes: list[dict], limit: int = 5) -> list[dict]:
    """System-wide changes (firewall, kernel settings) first, newest first within each: they are the ones that can stall a login."""
    def system(c: dict) -> bool:
        return "linux_hardening.sh" in c.get("undo", "") or "firewall" in c.get("what", "").lower() or "linux_firewall.sh" in c.get("undo", "")
    return sorted(changes, key=lambda c: (not system(c), -c.get("time", 0)))[:limit]


def _fmt(ts: float) -> str:
    return time.strftime("%b %d %H:%M", time.localtime(ts))


def slow_login_finding(login: dict, logins: list[dict]) -> dict:
    """The event for one slow login: how slow, compared with what, and which LinuxGuardian changes came since the last normal one."""
    normal = [entry for entry in logins if entry["seconds"] is not None and entry["seconds"] <= NORMAL_SECONDS and entry["start"] < login["start"]]
    since = normal[-1]["start"] if normal else 0.0
    changes = changes_between(since, login["start"])
    secs = login["seconds"]
    message = (f"Logging in took {secs:.0f} seconds on {_fmt(login['start'])}: the desktop sat at a black screen before it appeared"
               + (f" (the last normal login, {_fmt(since)}, took {normal[-1]['seconds']:.0f} s)." if normal else "."))
    if changes:
        message += (f" LinuxGuardian made {len(changes)} system change(s) since then: "
                    + "; ".join(f"{c['what']} ({_fmt(c['time'])}), undo with: {c['undo']}" for c in _ranked(changes))
                    + ". Undo the first one listed, then log out and back in to see if it helps.")
    else:
        # A change can take effect only at the next boot, so one made shortly before the last normal login is still a suspect.
        earlier = changes_between(since - 7 * 86400, since) if normal else []
        if earlier:
            message += (" LinuxGuardian made no system changes since then, but these came shortly before and some only take effect "
                        "after a reboot: " + "; ".join(f"{c['what']} ({_fmt(c['time'])}), undo with: {c['undo']}" for c in _ranked(earlier)) + ".")
            changes = earlier
        else:
            message += " LinuxGuardian made no system changes in the week before, so the cause is likely elsewhere (a driver, an update, a login script)."
    return {"key": f"login:slow:{int(login['start'])}", "severity": "warning", "event": "slow_login", "message": message,
            "entity": [], "technique": "", "stage": "", "extra": {"seconds": secs, "changes": _ranked(changes)}}


def run(state: dict, report: bool = True) -> list[dict]:
    """Sensor entry point: report each slow login once (state remembers which logins were already judged).
    With report=False (the sensors' first run, which only learns) logins are judged but nothing is reported."""
    logins = parse_logins(_journal_text())
    judged: dict = state.setdefault("logins_judged", {})
    recent = time.time() - 2 * 86400
    slow = []
    for login in logins:
        key = str(int(login["start"]))
        if login["seconds"] is None or key in judged:
            continue
        judged[key] = login["seconds"]
        if login["seconds"] > SLOW_SECONDS and login["start"] >= recent:
            slow.append(login)
    # Several slow logins found at once (the first run, or a morning of retries) are one story: report the latest.
    out = [slow_login_finding(slow[-1], logins)] if slow and report else []
    for key in sorted(judged, key=int)[:-KEEP_LOGINS]:
        del judged[key]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--mark-change", metavar="WHAT")
    ap.add_argument("--undo", default="")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.mark_change:
        try:
            mark_change(a.mark_change, a.undo)
        except OSError as exc:
            print(f"couldn't record the change: {exc}", file=sys.stderr)
            return 1
        return 0
    logins = parse_logins(_journal_text())[-10:]
    if a.json:
        print(json.dumps({"logins": logins, "changes": load_ledger()[-10:]}))
        return 0
    if not logins:
        print("No logins found in the journal (it may not be readable: add yourself to the 'adm' group).")
        return 0
    for entry in logins:
        secs = entry["seconds"]
        verdict = "never finished" if secs is None else ("SLOW" if secs > SLOW_SECONDS else "ok")
        print(f"{_fmt(entry['start'])}  {'?' if secs is None else f'{secs:6.1f} s'}  {verdict}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

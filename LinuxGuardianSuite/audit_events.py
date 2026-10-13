#!/usr/bin/env python3
"""Turn one audit run's findings into events, without repeating yourself.

The audit runs every time the app opens and on a schedule. Recording every warning on every run
buried real events (one machine collected 87 identical "no disk encryption" files in a month).
Instead this compares the findings against the previous run and writes an event only when a
finding is NEW, and a "resolved" event when one that was there has gone.

A finding you have decided to live with (full-disk encryption, for instance) can be ACCEPTED. It stays known and visible, but it is
no longer announced, no longer counted against the security rating, and no longer shows as something to fix. Accepting a finding
hides nothing else: a different finding, or a sensor's incident, is unaffected. You can stop accepting it at any time.

  audit_events.py                    reads lines of `severity<TAB>message` on stdin (what the audit pipes in)
  audit_events.py --accept TEXT      accept the finding whose message is TEXT
  audit_events.py --unaccept TEXT    stop accepting it
  audit_events.py --accepted         list accepted findings (json)
  audit_events.py --is-accepted TEXT exit 0 if accepted

Test hook: LG_HOME.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

from events import SEVERITIES, lg_home, record_event  # noqa: E402


def key_of(message: str) -> str:
    """A count changing ("17 updates" -> "16 updates") is the same finding, not a new one."""
    return re.sub(r"\d+", "N", message.split(" — ")[0]).strip().lower()


def state_path() -> Path:
    return lg_home() / "state" / "audit.json"


def accepted_path() -> Path:
    return lg_home() / "state" / "accepted_risks.json"


def load_accepted() -> dict[str, dict]:
    try:
        data = json.loads(accepted_path().read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_accepted(data: dict) -> None:
    path = accepted_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.replace(path)


def is_accepted(message: str) -> bool:
    return key_of(message) in load_accepted()


def accept(message: str) -> str:
    """Accept this finding (it is identified the same way the audit identifies it: a changing count is still the same finding)."""
    if not message.strip():
        raise ValueError("nothing to accept")
    key = key_of(message)
    data = load_accepted()
    if key not in data:
        data[key] = {"message": message.split(" — ")[0].strip(), "time": time.time()}
        _save_accepted(data)
        record_event("audit", "info", "risk_accepted", f"Accepted risk: {data[key]['message']}", status="detected")
    return key


def unaccept(message: str) -> bool:
    key = key_of(message)
    data = load_accepted()
    if key not in data:
        return False
    del data[key]
    _save_accepted(data)
    # forget that it was known, so it is announced as new again if it is still true
    prev = load_previous()
    if key in prev:
        del prev[key]
        _write_previous(prev)
    return True


def load_previous() -> dict[str, dict]:
    try:
        data = json.loads(state_path().read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def process(findings: list[tuple[str, str]]) -> tuple[int, int]:
    """Returns (new_events, resolved_events)."""
    previous = load_previous()
    accepted = load_accepted()
    current: dict[str, dict] = {}
    new = 0
    for severity, message in findings:
        if severity not in SEVERITIES or not message:
            continue
        key = key_of(message)
        current[key] = {"severity": severity, "message": message}
        if key in accepted:
            current[key]["accepted"] = True                 # known and visible, but not announced
            continue
        if key not in previous:
            record_event("audit", severity, "audit_finding", message, status="detected")
            new += 1
    resolved = 0
    for key, old in previous.items():
        if key not in current and key not in accepted:
            record_event("audit", "info", "audit_finding", f"Resolved: {old.get('message', key)}", status="resolved")
            resolved += 1
    _write_previous(current)
    return new, resolved


def _write_previous(data: dict) -> None:
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.replace(path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--accept", metavar="TEXT")
    g.add_argument("--unaccept", metavar="TEXT")
    g.add_argument("--accepted", action="store_true")
    g.add_argument("--is-accepted", metavar="TEXT")
    a = ap.parse_args()
    if a.accept is not None:
        try:
            accept(a.accept)
        except ValueError as exc:
            print(f"[error] {exc}", file=sys.stderr)
            return 1
        print("Accepted: this finding stays visible but is no longer announced or counted against the rating.")
        return 0
    if a.unaccept is not None:
        print("No longer accepted." if unaccept(a.unaccept) else "That finding wasn't accepted.")
        return 0
    if a.accepted:
        print(json.dumps([{"key": k, **v} for k, v in load_accepted().items()]))
        return 0
    if a.is_accepted is not None:
        return 0 if is_accepted(a.is_accepted) else 1
    findings = []
    for line in sys.stdin:
        severity, _, message = line.rstrip("\n").partition("\t")
        findings.append((severity, message))
    process(findings)
    return 0


if __name__ == "__main__":
    sys.exit(main())

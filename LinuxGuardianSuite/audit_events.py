#!/usr/bin/env python3
"""Turn one audit run's findings into events, without repeating yourself.

The audit runs every time the app opens and on a schedule. Recording every warning on every run
buried real events (one machine collected 87 identical "no disk encryption" files in a month).
Instead this compares the findings against the previous run and writes an event only when a
finding is NEW, and a "resolved" event when one that was there has gone.

Reads lines of `severity<TAB>message` on stdin. Test hook: LG_HOME.
"""
from __future__ import annotations

import json
import re
import sys
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


def load_previous() -> dict[str, dict]:
    try:
        data = json.loads(state_path().read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def process(findings: list[tuple[str, str]]) -> tuple[int, int]:
    """Returns (new_events, resolved_events)."""
    previous = load_previous()
    current: dict[str, dict] = {}
    new = 0
    for severity, message in findings:
        if severity not in SEVERITIES or not message:
            continue
        key = key_of(message)
        current[key] = {"severity": severity, "message": message}
        if key not in previous:
            record_event("audit", severity, "audit_finding", message, status="detected")
            new += 1
    resolved = 0
    for key, old in previous.items():
        if key not in current:
            record_event("audit", "info", "audit_finding", f"Resolved: {old.get('message', key)}", status="resolved")
            resolved += 1
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(current))
    tmp.replace(path)
    return new, resolved


def main() -> int:
    findings = []
    for line in sys.stdin:
        severity, _, message = line.rstrip("\n").partition("\t")
        findings.append((severity, message))
    process(findings)
    return 0


if __name__ == "__main__":
    sys.exit(main())

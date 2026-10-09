#!/usr/bin/env python3
"""One place that defines what a LinuxGuardian security event looks like.

Scripts already write small JSON files into ~/.linuxguardian/incidents/ (see
`lg_record_incident` in utils.sh): {timestamp, category, severity, message}.
This module keeps that exact format as the required core and adds *optional*
structured fields, so newer detectors can say what happened in a way a future
timeline, notification or anomaly detector can use without parsing sentences:

    {
      "timestamp": "2026-10-07T19:30:00-0700",
      "category":  "network",            # what area: network, integrity, malware, ...
      "severity":  "warning",            # info | warning | critical  (same words as before)
      "message":   "VNC is reachable ...",   # human sentence; always present
      "event":     "exposed_service",    # machine name for what happened
      "status":    "detected",           # detected | changed | resolved
      "process":   "vino-server", "pid": 5517, "port": 5900, "protocol": "tcp"
    }

Old records (written by the shell helper, with only the four core fields)
are still valid and readable. Nothing here ever takes an action: events are a
record of what was *seen*.
"""
from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path

SEVERITIES = ("info", "warning", "critical")
STATUSES = ("detected", "changed", "resolved")


def lg_home() -> Path:
    return Path(os.environ.get("LG_HOME", str(Path.home() / ".linuxguardian")))


def incident_dir() -> Path:
    return lg_home() / "incidents"


def record_event(
    category: str,
    severity: str,
    event: str,
    message: str,
    *,
    status: str = "detected",
    **extra: object,
) -> Path:
    """Write one event file and return its path. Raises ValueError on bad input
    rather than writing something later code can't interpret."""
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}, got {severity!r}")
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}, got {status!r}")
    if not category or not event or not message:
        raise ValueError("category, event and message are required")
    reserved = {"timestamp", "category", "severity", "message", "event", "status"}
    clash = reserved & extra.keys()
    if clash:
        raise ValueError(f"extra fields can't reuse core names: {sorted(clash)}")

    record: dict[str, object] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "category": category,
        "severity": severity,
        "message": message,
        "event": event,
        "status": status,
    }
    record.update({k: v for k, v in extra.items() if v is not None})

    directory = incident_dir()
    directory.mkdir(parents=True, exist_ok=True)
    name = f"{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}-{secrets.randbelow(100000)}.json"
    final = directory / name
    # Write-then-rename so a reader never sees a half-written file.
    tmp = directory / f".{name}.tmp"
    tmp.write_text(json.dumps(record, ensure_ascii=False) + "\n")
    os.replace(tmp, final)
    return final


def read_events(directory: Path | None = None, limit: int = 200) -> list[dict]:
    """Newest-first list of events. Tolerates old-format records and junk files."""
    directory = directory or incident_dir()
    if not directory.is_dir():
        return []
    events: list[dict] = []
    for path in sorted(directory.glob("*.json"), reverse=True):
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict) or "severity" not in data or "message" not in data:
            continue
        events.append(data)
        if len(events) >= limit:
            break
    return events

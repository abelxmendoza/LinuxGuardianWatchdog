#!/usr/bin/env python3
"""Security timeline: what has been seen on this machine, newest first, without the noise.

Reads the event files in ~/.linuxguardian/incidents/ (see events.py). Detectors that run
often write the same finding again and again (one real machine had 87 identical "no disk
encryption" records), so identical findings are folded into ONE entry with a count and a
first/last-seen range. Read-only: nothing is deleted. "Acknowledge" only records that you have
seen a finding; it comes back on its own if the finding is seen again afterwards.

  timeline.py [--days N] [--min-severity info|warning|critical] [--category C]
              [--search TEXT] [--all] [--json|--text]
  timeline.py --ack KEY            mark an entry as seen (KEY from --json)
  timeline.py --unack KEY

Test hook: LG_HOME.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

from events import SEVERITIES, incident_dir, lg_home  # noqa: E402

RANK = {"info": 0, "warning": 1, "critical": 2}
_FILENAME_TS = re.compile(r"^(\d{8})-(\d{6})")


@dataclass
class Entry:
    key: str
    category: str
    severity: str
    status: str
    message: str
    count: int
    first_ts: float
    last_ts: float
    acknowledged: bool = False
    extra: dict = field(default_factory=dict)


def _state_path() -> Path:
    return lg_home() / "state" / "timeline_ack.json"


def load_acks() -> dict[str, float]:
    try:
        data = json.loads(_state_path().read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return {k: float(v) for k, v in data.items()} if isinstance(data, dict) else {}


def _save_acks(acks: dict[str, float]) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(acks))
    tmp.replace(path)


def acknowledge(key: str, now: float | None = None) -> None:
    acks = load_acks()
    acks[key] = time.time() if now is None else now
    _save_acks(acks)


def unacknowledge(key: str) -> None:
    acks = load_acks()
    if acks.pop(key, None) is not None:
        _save_acks(acks)


def _epoch(record: dict, path: Path) -> float:
    ts = record.get("timestamp")
    if isinstance(ts, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(ts, fmt).timestamp()
            except ValueError:
                pass
    match = _FILENAME_TS.match(path.name)
    if match:
        try:
            return datetime.strptime("".join(match.groups()), "%Y%m%d%H%M%S").timestamp()
        except ValueError:
            pass
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def fingerprint(category: str, severity: str, status: str, message: str) -> str:
    """Same finding => same key, even when a number in it changes ("17 updates" vs "16 updates")."""
    normalized = re.sub(r"\d+", "N", message).strip().lower()
    return f"{category}|{severity}|{status}|{normalized}"


def load_entries(directory: Path | None = None) -> list[Entry]:
    directory = directory or incident_dir()
    if not directory.is_dir():
        return []
    folded: dict[str, Entry] = {}
    for path in directory.glob("*.json"):
        try:
            record = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(record, dict) or record.get("severity") not in SEVERITIES or not record.get("message"):
            continue
        ts = _epoch(record, path)
        category = str(record.get("category") or "other")
        status = str(record.get("status") or "detected")
        message = str(record["message"])
        key = fingerprint(category, record["severity"], status, message)
        entry = folded.get(key)
        if entry is None:
            extra = {k: v for k, v in record.items()
                     if k not in {"timestamp", "category", "severity", "message", "status"}}
            folded[key] = Entry(key, category, record["severity"], status, message, 1, ts, ts, extra=extra)
        else:
            entry.count += 1
            if ts >= entry.last_ts:
                entry.last_ts, entry.message = ts, message     # show the latest wording (latest counts)
            entry.first_ts = min(entry.first_ts, ts)
    acks = load_acks()
    for entry in folded.values():
        entry.acknowledged = entry.key in acks and entry.last_ts <= acks[entry.key]
    return sorted(folded.values(), key=lambda e: e.last_ts, reverse=True)


def select(
    entries: list[Entry],
    *,
    now: float | None = None,
    days: float | None = None,
    min_severity: str = "info",
    category: str | None = None,
    search: str | None = None,
    include_acknowledged: bool = False,
) -> list[Entry]:
    now = time.time() if now is None else now
    needle = (search or "").lower()
    out = []
    for e in entries:
        if days is not None and e.last_ts < now - days * 86400:
            continue
        if RANK[e.severity] < RANK[min_severity]:
            continue
        if category and e.category != category:
            continue
        if needle and needle not in e.message.lower() and needle not in e.category.lower():
            continue
        if e.acknowledged and not include_acknowledged:
            continue
        out.append(e)
    return out


def summarize(entries: list[Entry]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for e in entries:
        if e.status != "resolved":
            counts[e.severity] += 1
    return counts


def fmt_when(ts: float, now: float | None = None) -> str:
    now = time.time() if now is None else now
    day = datetime.fromtimestamp(ts).date()
    today = datetime.fromtimestamp(now).date()
    clock = datetime.fromtimestamp(ts).strftime("%H:%M")
    delta = (today - day).days
    if delta == 0:
        return f"today {clock}"
    if delta == 1:
        return f"yesterday {clock}"
    return datetime.fromtimestamp(ts).strftime("%b %d %H:%M").replace(" 0", " ")


def render_text(entries: list[Entry], now: float | None = None) -> str:
    if not entries:
        return "Nothing to show."
    lines = []
    for e in entries:
        times = f" (x{e.count}, since {fmt_when(e.first_ts, now)})" if e.count > 1 else ""
        mark = " [seen]" if e.acknowledged else ""
        lines.append(f"{fmt_when(e.last_ts, now):>18}  {e.severity.upper():8} {e.category:10} {e.message}{times}{mark}")
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--days", type=float)
    p.add_argument("--min-severity", choices=SEVERITIES, default="info")
    p.add_argument("--category")
    p.add_argument("--search")
    p.add_argument("--all", action="store_true", help="include acknowledged entries")
    p.add_argument("--json", action="store_true")
    p.add_argument("--text", action="store_true")
    p.add_argument("--ack", metavar="KEY")
    p.add_argument("--unack", metavar="KEY")
    args = p.parse_args()
    if args.ack:
        acknowledge(args.ack)
        return 0
    if args.unack:
        unacknowledge(args.unack)
        return 0
    entries = select(load_entries(), days=args.days, min_severity=args.min_severity, category=args.category,
                     search=args.search, include_acknowledged=args.all)
    if args.json:
        print(json.dumps([asdict(e) for e in entries]))
    else:
        print(render_text(entries))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Persist ClamAV / rkhunter scan summaries under ~/.linuxguardian/scans/.

The GUI reads last.json; this tool is also invoked by linux_guardian.sh.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime
from pathlib import Path

HOME = Path(os.environ.get("LG_HOME", Path.home() / ".linuxguardian"))
SCAN_DIR = HOME / "scans"
LAST_PATH = SCAN_DIR / "last.json"
HISTORY_DIR = SCAN_DIR / "history"
DEFAULT_LOG_DIR = HOME / "logs" / "scans"

_SUMMARY = {
    "known_viruses": re.compile(r"Known viruses:\s*(\d+)"),
    "engine_version": re.compile(r"Engine version:\s*(\S+)"),
    "directories": re.compile(r"Scanned directories:\s*(\d+)"),
    "files": re.compile(r"Scanned files:\s*(\d+)"),
    "infected": re.compile(r"Infected files:\s*(\d+)"),
    "errors": re.compile(r"Total errors:\s*(\d+)"),
    "data_scanned": re.compile(r"Data scanned:\s*(.+)"),
    "data_read": re.compile(r"Data read:\s*([^(]+)"),
    "duration_sec": re.compile(r"Time:\s*([\d.]+)\s*sec"),
    "start_date": re.compile(r"Start Date:\s*(\d{4}:\d{2}:\d{2}\s+\d{2}:\d{2}:\d{2})"),
    "end_date": re.compile(r"End Date:\s*(\d{4}:\d{2}:\d{2}\s+\d{2}:\d{2}:\d{2})"),
}


def _parse_clam_date(value: str) -> datetime | None:
    try:
        return datetime.strptime(value.strip(), "%Y:%m:%d %H:%M:%S")
    except ValueError:
        return None


def parse_clam_log(path: Path) -> dict:
    text = path.read_text(errors="replace")
    found = {}
    for key, regex in _SUMMARY.items():
        match = regex.search(text)
        if match:
            found[key] = match.group(1).strip()
    infected_hits = len(re.findall(r"FOUND$", text, re.M))
    result = {
        "schema": 1,
        "engine": "clamscan",
        "engine_version": found.get("engine_version", ""),
        "known_viruses": int(found["known_viruses"]) if "known_viruses" in found else None,
        "directories": int(found["directories"]) if "directories" in found else None,
        "files": int(found["files"]) if "files" in found else None,
        "infected": int(found["infected"]) if "infected" in found else infected_hits,
        "errors": int(found["errors"]) if "errors" in found else 0,
        "data_scanned": found.get("data_scanned", ""),
        "data_read": found.get("data_read", ""),
        "duration_sec": int(float(found["duration_sec"])) if "duration_sec" in found else None,
        "report": str(path),
        "found_lines": infected_hits,
    }
    start = _parse_clam_date(found["start_date"]) if "start_date" in found else None
    end = _parse_clam_date(found["end_date"]) if "end_date" in found else None
    if start:
        result["started_epoch"] = int(start.timestamp())
        result["timestamp_start"] = start.isoformat(timespec="seconds")
    if end:
        result["ended_epoch"] = int(end.timestamp())
        result["timestamp"] = end.isoformat(timespec="seconds")
    elif start and result.get("duration_sec"):
        result["ended_epoch"] = int(start.timestamp()) + int(result["duration_sec"])
        result["timestamp"] = datetime.fromtimestamp(result["ended_epoch"]).isoformat(timespec="seconds")
    return result


def _summary_number(text: str, label: str) -> int:
    match = re.search(rf"^[\t ]*{label}\s*:\s*(\d+)", text, re.M | re.I)
    return int(match.group(1)) if match else 0


def rkhunter_warning_count(path: Path | None) -> int:
    """How many things rkhunter flagged. Counts every form it can report them in.

    The console shows `<check> [ Warning ]`; the log-style form is `Warning: ...`; and the closing
    summary gives "Suspect files" / "Possible rootkits" totals. The largest of these wins, and
    "One or more warnings" guarantees at least 1, so a scan that flagged something is never "0".
    """
    if path is None or not path.is_file() or path.stat().st_size == 0:
        return 0
    text = path.read_text(errors="replace")
    log_style = len(re.findall(r"^[\t ]*Warning:", text, re.M | re.I))
    console = len(re.findall(r"\[\s*Warning\s*\]", text))
    summary = _summary_number(text, "Suspect files") + _summary_number(text, "Possible rootkits")
    n = max(log_style, console, summary)
    if n:
        return n
    if re.search(r"one or more warnings", text, re.I):
        return 1
    return 0


def rootkit_check_status(path: Path | None, rc: int | None = None) -> str:
    """Did the rootkit scanner actually scan?
    'ran' | 'needs_root' | 'cancelled' | 'not_run'.

    `rc` is the exit status if known: pkexec returns 126/127 when the password
    prompt was dismissed or authentication failed, which leaves no log at all.

    rkhunter refuses to run for a normal user: it prints "You must be the root
    user to run this program." and exits at once. That leaves a tiny log, zero
    warnings, and a non-zero exit, which is easy to misread as "no rootkit
    warnings". Real scan logs are many KB, so a short log with that sentence
    means the scan never happened.
    """
    if path is None or not path.is_file() or path.stat().st_size == 0:
        return "cancelled" if rc in (126, 127) else "not_run"
    text = path.read_text(errors="replace")
    if len(text) < 500 and re.search(r"must be (the )?root", text, re.I):
        return "needs_root"
    return "ran"


def rkhunter_property_change_count(path: Path | None) -> int:
    """Warnings that just mean "a file differs from rkhunter's baseline".

    Right after package updates these are expected (rkhunter's baseline isn't refreshed
    automatically on Ubuntu), so they're reported separately instead of all being presented as
    possible rootkits. Uses the "Suspect files" total from the summary when present.
    """
    if path is None or not path.is_file():
        return 0
    text = path.read_text(errors="replace")
    log_style = len(re.findall(r"^[\t ]*Warning: The file properties have changed", text, re.M | re.I))
    return max(log_style, _summary_number(text, "Suspect files"))


def save_result(result: dict) -> Path:
    SCAN_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    LAST_PATH.write_text(json.dumps(result, indent=2) + "\n")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    history = HISTORY_DIR / f"{stamp}.json"
    history.write_text(json.dumps(result, indent=2) + "\n")
    _prune_history(30)
    return LAST_PATH


def load_last() -> dict | None:
    if not LAST_PATH.is_file():
        return None
    try:
        data = json.loads(LAST_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def import_latest_log(log_dir: Path | None = None, **extra: object) -> dict | None:
    directory = log_dir or DEFAULT_LOG_DIR
    logs = sorted(directory.glob("clamscan-*.log"), key=lambda p: p.stat().st_mtime)
    # Prefer a log that actually has a SCAN SUMMARY.
    chosen = None
    for path in reversed(logs):
        try:
            if "SCAN SUMMARY" in path.read_text(errors="replace"):
                chosen = path
                break
        except OSError:
            continue
    if chosen is None:
        return None
    result = parse_clam_log(chosen)
    result.update({k: v for k, v in extra.items() if v is not None})
    stamp = chosen.name.replace("clamscan-", "").replace(".log", "")
    rk = directory / f"rkhunter-{stamp}.log"
    if rk.is_file():
        result["rk_report"] = str(rk)
        result["rootkit_check"] = rootkit_check_status(rk)
        if result["rootkit_check"] == "ran":
            result["rkhunter_warnings"] = rkhunter_warning_count(rk)
    save_result(result)
    return result


def _prune_history(keep: int) -> None:
    files = sorted(HISTORY_DIR.glob("*.json"), key=lambda p: p.name, reverse=True)
    for stale in files[keep:]:
        try:
            stale.unlink()
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    save = sub.add_parser("save", help="Record a scan from a ClamAV log")
    save.add_argument("--from-log", required=True, type=Path)
    save.add_argument("--rk-log", type=Path)
    save.add_argument("--target", default="")
    save.add_argument("--mode", default="quick")
    save.add_argument("--changed-only", action="store_true")
    save.add_argument("--engine", default="clamscan")
    save.add_argument("--clam-rc", type=int, default=0)
    save.add_argument("--rk-rc", type=int)
    save.add_argument("--rk-status", choices=("ran", "needs_root", "cancelled", "not_run"),
                      help="what the shell knows about the rootkit check (wins over guessing from the log)")
    save.add_argument("--excludes", default="")
    sub.add_parser("last", help="Print last.json as JSON")
    sub.add_parser("import-latest", help="Import the newest complete clamscan log")
    args = parser.parse_args()

    if args.cmd == "last":
        data = load_last()
        if not data:
            return 1
        print(json.dumps(data, indent=2))
        return 0

    if args.cmd == "import-latest":
        result = import_latest_log()
        if not result:
            return 1
        print(json.dumps(result, indent=2))
        return 0

    result = parse_clam_log(args.from_log)
    result.update(
        {
            "target": args.target,
            "mode": args.mode,
            "changed_only": bool(args.changed_only),
            "engine": args.engine,
            "clam_rc": args.clam_rc,
            "excludes": args.excludes,
        }
    )
    if args.rk_log:
        result["rk_report"] = str(args.rk_log)
    if args.rk_log or args.rk_status:
        result["rootkit_check"] = args.rk_status or rootkit_check_status(args.rk_log, args.rk_rc)
        # "0 warnings" is only meaningful if the scanner actually ran.
        if result["rootkit_check"] == "ran":
            result["rkhunter_warnings"] = rkhunter_warning_count(args.rk_log)
            result["rkhunter_property_changes"] = rkhunter_property_change_count(args.rk_log)
    if args.rk_rc is not None:
        result["rkhunter_rc"] = args.rk_rc
    if "timestamp" not in result:
        result["timestamp"] = datetime.now().isoformat(timespec="seconds")
        result["ended_epoch"] = int(datetime.now().timestamp())
    save_result(result)
    print(str(LAST_PATH))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

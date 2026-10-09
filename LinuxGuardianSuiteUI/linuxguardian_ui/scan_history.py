"""Load the last persisted malware scan for the dashboard."""
from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from linuxguardian_ui.progress import format_duration
from linuxguardian_ui.scripts import SUITE_DIR

if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))
from scan_store import rootkit_check_status  # noqa: E402  (single source of truth for this rule)

LAST_PATH = Path.home() / ".linuxguardian" / "scans" / "last.json"


def load_last_scan() -> dict | None:
    if not LAST_PATH.is_file():
        return None
    try:
        data = json.loads(LAST_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def ensure_last_scan() -> dict | None:
    data = load_last_scan()
    if data:
        return data
    store = SUITE_DIR / "scan_store.py"
    if not store.is_file():
        return None
    try:
        subprocess.run(
            [sys.executable, str(store), "import-latest"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return load_last_scan()


def rootkit_status(data: dict) -> str:
    """'ran' | 'needs_root' | 'cancelled' | 'not_run'. Records saved before this field existed
    are classified from their rkhunter log, so old results get the same honesty."""
    status = data.get("rootkit_check")
    if status in ("ran", "needs_root", "cancelled", "not_run"):
        return status
    report = data.get("rk_report")
    return rootkit_check_status(Path(report)) if report else "not_run"


def coverage_incomplete(data: dict) -> bool:
    """ClamAV could not read everything it was pointed at, or died part-way.

    Unreadable files count; so does an exit status that isn't clean/infected. Status 2 on its own
    (with a finished summary and zero counted errors) is the usual "a temp file vanished mid-scan",
    and is deliberately not alarming.
    """
    return int(data.get("errors") or 0) > 0 or data.get("clam_rc") not in (None, 0, 1, 2)


def rootkit_errored(data: dict) -> bool:
    """rkhunter produced no usable verdict: it exited non-zero without reporting any warnings.

    Status "not_run" is included for records saved before `rootkit_check` existed that carry only an
    exit status. "needs_root" never counts: that is a known skip, not an error.
    """
    return (
        rootkit_status(data) in ("ran", "not_run")
        and not int(data.get("rkhunter_warnings") or 0)
        and data.get("rkhunter_rc") not in (None, 0)
    )


def last_scan_severity(data: dict) -> str:
    """'critical' | 'warning' | 'ok' for coloring the card. A scan whose rootkit
    half never ran is a warning, not a pass."""
    if int(data.get("infected") or 0) > 0:
        return "critical"
    if data.get("files") is None:
        return "warning"
    status = rootkit_status(data)
    if status != "ran" or int(data.get("rkhunter_warnings") or 0) > 0:
        return "warning"
    if coverage_incomplete(data) or rootkit_errored(data):
        return "warning"
    return "ok"


def format_last_scan(data: dict) -> tuple[str, str]:
    """Return (title, detail) for the last-scan card.

    "Clean" is only claimed when BOTH scanners ran and found nothing. If the
    rootkit check didn't run, the title says only what is true (no malware
    found) and the detail says what was skipped.
    """
    infected = int(data.get("infected") or 0)
    files = data.get("files")
    duration = data.get("duration_sec")
    errors = int(data.get("errors") or 0)
    mode = data.get("mode") or "full"
    changed = data.get("changed_only")
    when = _when(data)
    status = rootkit_status(data)
    rk_warnings = int(data.get("rkhunter_warnings") or 0) if status == "ran" else 0
    incomplete = coverage_incomplete(data)
    rk_error = rootkit_errored(data)

    if infected:
        title = f"{infected} infected"
    elif files is None:
        title = "Scan incomplete"
    elif rk_warnings:
        title = f"{rk_warnings} rootkit warning{'s' if rk_warnings != 1 else ''}"
    elif incomplete or rk_error:
        title = "Scan needs review"
    elif status == "ran":
        title = "Clean"
    else:
        title = "No malware found"

    bits = [when] if when else []
    if files is not None:
        bits.append(f"{int(files):,} files")
    if duration is not None:
        bits.append(format_duration(float(duration)))
    if errors:
        bits.append(f"{errors} unreadable")
    kind = "quick scan" if mode == "quick" else "full scan"
    if changed:
        kind = "changed-files " + kind
    bits.append(kind)
    if incomplete:
        bits.append("ClamAV coverage incomplete or unverified")
    if status == "needs_root":
        bits.append("rootkit check skipped (needs root)")
    elif status == "cancelled":
        bits.append("rootkit check cancelled (password prompt dismissed)")
    elif status == "not_run" and not rk_error:
        bits.append("rootkit check not run")
    elif rk_warnings:
        changed_files = min(int(data.get("rkhunter_property_changes") or 0), rk_warnings)
        if changed_files == rk_warnings:
            bits.append("all are changed files, normal right after updates")
        elif changed_files:
            bits.append(f"{changed_files} are changed files, normal right after updates")
        else:
            bits.append("Rootkit check needs review; see its report")
    if rk_error:
        bits.append("Rootkit check needs review; see its report")
    return title, " · ".join(bits)


def _when(data: dict) -> str:
    epoch = data.get("ended_epoch")
    if not epoch:
        ts = data.get("timestamp") or ""
        return ts.replace("T", " ")[:16]
    try:
        delta = max(0, int(time.time() - int(epoch)))
    except (TypeError, ValueError):
        return ""
    if delta < 90:
        return "just now"
    if delta < 3600:
        return f"{delta // 60} min ago"
    if delta < 86400:
        hours = delta // 3600
        return f"{hours}h ago"
    dt = datetime.fromtimestamp(int(epoch))
    return dt.strftime("%Y-%m-%d %H:%M")

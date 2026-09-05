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


def format_last_scan(data: dict) -> tuple[str, str]:
    """Return (title, detail) for the last-scan card."""
    infected = int(data.get("infected") or 0)
    files = data.get("files")
    duration = data.get("duration_sec")
    errors = int(data.get("errors") or 0)
    mode = data.get("mode") or "full"
    changed = data.get("changed_only")
    when = _when(data)
    title = "Clean" if infected == 0 else f"{infected} infected"
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

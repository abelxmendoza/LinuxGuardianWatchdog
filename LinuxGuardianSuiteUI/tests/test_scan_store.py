"""Tests for scan result persistence and dashboard formatting."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))
sys.path.insert(0, str(ROOT / "LinuxGuardianSuiteUI"))

from scan_store import parse_clam_log  # noqa: E402
from linuxguardian_ui.scan_history import format_last_scan  # noqa: E402

SAMPLE = ROOT / "LinuxGuardianSuiteUI" / "tests" / "clamscan-sample.log"


def test_parse_clam_log(tmp_path: Path | None = None) -> None:
    log = SAMPLE if SAMPLE.is_file() else None
    if log is None:
        raise SystemExit("missing sample log")
    result = parse_clam_log(log)
    assert result["infected"] == 0
    assert result["files"] == 717433
    assert result["directories"] == 113737
    assert result["errors"] == 79
    assert result["duration_sec"] == 7335
    assert result["engine_version"] == "1.5.3"
    assert result["ended_epoch"]


def test_format_last_scan() -> None:
    title, detail = format_last_scan(
        {
            "infected": 0,
            "files": 717433,
            "duration_sec": 7335,
            "errors": 79,
            "mode": "full",
            "ended_epoch": 1,
        }
    )
    assert title == "Scan needs review"
    assert "717,433 files" in detail
    assert "full scan" in detail


if __name__ == "__main__":
    # Copy real scan log as sample if present.
    real = Path.home() / ".linuxguardian/logs/scans/clamscan-20260904-192648.log"
    if real.is_file() and not SAMPLE.is_file():
        SAMPLE.parent.mkdir(parents=True, exist_ok=True)
        SAMPLE.write_text(real.read_text())
    test_parse_clam_log()
    test_format_last_scan()
    print("OK")


def test_rootkit_failure_not_clean():
    title, detail = format_last_scan({"files": 761, "infected": 0, "errors": 0,
                                     "clam_rc": 0, "rkhunter_rc": 1})
    assert title == "Scan needs review"
    assert "Rootkit check needs review" in detail


def test_completed_scan_no_detections():
    title, _ = format_last_scan({"files": 10, "infected": 0, "errors": 0,
                                "clam_rc": 0, "rkhunter_rc": 0})
    assert title == "No detections"

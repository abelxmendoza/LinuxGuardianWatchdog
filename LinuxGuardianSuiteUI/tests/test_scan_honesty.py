"""The scan result must say what actually ran.

Regression: rkhunter needs root. Run as a normal user it prints "You must be the
root user to run this program." and exits at once, leaving a 47-byte log, zero
warnings and a non-zero exit. The app saved `rkhunter_warnings: 0` and the
Dashboard said "Clean", i.e. it claimed a rootkit check that never happened.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))
sys.path.insert(0, str(ROOT / "LinuxGuardianSuiteUI"))

import scan_store  # noqa: E402
from linuxguardian_ui.scan_history import (  # noqa: E402
    format_last_scan,
    last_scan_severity,
    rootkit_status,
)

ROOT_ERROR = "You must be the root user to run this program.\n"  # exactly what rkhunter printed here
REAL_RKHUNTER_LOG = (
    "[ Rootkit Hunter version 1.4.6 ]\n\nChecking system commands...\n\n"
    "  Performing 'strings' command checks\n    Checking 'strings' command                               [ OK ]\n"
    + "  Checking file properties of /usr/bin/awk                     [ OK ]\n" * 20
    + "\nSystem checks summary\n=====================\n\nFile properties checks...\n    Files checked: 142\n"
    "    Suspect files: 0\n\nRootkit checks...\n    Rootkits checked : 497\n    Possible rootkits: 0\n"
)
SAMPLE_CLAM = ROOT / "LinuxGuardianSuiteUI" / "tests" / "clamscan-sample.log"


def rk_log(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "rkhunter.log"
    path.write_text(text)
    return path


# --------------------------------------------------------------- classifier
def test_status_not_run_when_there_is_no_log(tmp_path: Path) -> None:
    assert scan_store.rootkit_check_status(None) == "not_run"
    assert scan_store.rootkit_check_status(tmp_path / "missing.log") == "not_run"
    assert scan_store.rootkit_check_status(rk_log(tmp_path, "")) == "not_run"


def test_status_needs_root_for_the_real_error_message(tmp_path: Path) -> None:
    assert scan_store.rootkit_check_status(rk_log(tmp_path, ROOT_ERROR)) == "needs_root"
    assert scan_store.rootkit_check_status(rk_log(tmp_path, "You must be root to run this\n")) == "needs_root"


def test_status_ran_for_a_real_scan_log(tmp_path: Path) -> None:
    assert len(REAL_RKHUNTER_LOG) > 500
    assert scan_store.rootkit_check_status(rk_log(tmp_path, REAL_RKHUNTER_LOG)) == "ran"


def test_a_long_log_that_merely_mentions_root_is_still_a_real_scan(tmp_path: Path) -> None:
    # Only a SHORT log counts as "refused to run"; a full scan can legitimately say "root" somewhere.
    text = REAL_RKHUNTER_LOG + "Note: some checks are more thorough when you must be root.\n"
    assert scan_store.rootkit_check_status(rk_log(tmp_path, text)) == "ran"


# ------------------------------------------------------------------ the card
BASE = {"infected": 0, "files": 34946, "duration_sec": 357, "errors": 0, "mode": "quick", "ended_epoch": 1}


def card(**extra: object) -> tuple[str, str]:
    return format_last_scan({**BASE, **extra})


def test_clean_is_only_claimed_when_the_rootkit_check_ran() -> None:
    title, detail = card(rootkit_check="ran", rkhunter_warnings=0)
    assert title == "Clean"
    assert "rootkit" not in detail


def test_no_rootkit_check_means_only_what_is_true() -> None:
    title, detail = card(rootkit_check="needs_root")
    assert title == "No malware found"            # not "Clean"
    assert "rootkit check skipped (needs root)" in detail
    title, detail = card(rootkit_check="not_run")
    assert title == "No malware found" and "rootkit check not run" in detail


def test_a_record_with_no_rootkit_information_does_not_claim_clean() -> None:
    title, detail = card()
    assert title == "No malware found" and "rootkit check not run" in detail


def test_rootkit_warnings_and_infections_take_priority() -> None:
    assert card(rootkit_check="ran", rkhunter_warnings=3)[0] == "3 rootkit warnings"
    assert card(rootkit_check="ran", rkhunter_warnings=1)[0] == "1 rootkit warning"
    assert card(infected=2, rootkit_check="ran", rkhunter_warnings=0)[0] == "2 infected"
    assert card(infected=2, rootkit_check="needs_root")[0] == "2 infected"


def test_zero_warnings_from_a_scanner_that_never_ran_is_ignored() -> None:
    # The old records said rkhunter_warnings: 0 even though nothing ran.
    title, _ = card(rootkit_check="needs_root", rkhunter_warnings=0)
    assert title != "Clean"


def test_an_incomplete_scan_is_called_incomplete() -> None:
    title, _ = format_last_scan({"infected": 0, "mode": "quick", "ended_epoch": 1, "rootkit_check": "ran"})
    assert title == "Scan incomplete"


def test_clamav_exit_2_with_a_finished_summary_is_not_alarming() -> None:
    # exit 2 here was just "Can't access file" for temp files deleted mid-scan.
    title, _ = card(rootkit_check="ran", rkhunter_warnings=0, clam_rc=2)
    assert title == "Clean"


# ------------------------------------------------------------------- severity
def test_severity() -> None:
    assert last_scan_severity({**BASE, "rootkit_check": "ran", "rkhunter_warnings": 0}) == "ok"
    assert last_scan_severity({**BASE, "rootkit_check": "needs_root"}) == "warning"
    assert last_scan_severity({**BASE, "rootkit_check": "ran", "rkhunter_warnings": 2}) == "warning"
    assert last_scan_severity({**BASE, "infected": 1, "rootkit_check": "ran"}) == "critical"
    assert last_scan_severity({"infected": 0, "mode": "quick"}) == "warning"   # no summary => incomplete


# ----------------------------------------------- records saved before the fix
def test_old_records_are_classified_from_their_rkhunter_log(tmp_path: Path) -> None:
    old = {**BASE, "rk_report": str(rk_log(tmp_path, ROOT_ERROR)), "rkhunter_warnings": 0, "rkhunter_rc": 1}
    assert "rootkit_check" not in old
    assert rootkit_status(old) == "needs_root"
    assert card(**{k: v for k, v in old.items() if k not in BASE})[0] == "No malware found"
    # the explicit field wins over re-inspecting the log
    assert rootkit_status({**old, "rootkit_check": "ran"}) == "ran"


def test_the_exact_record_from_the_real_machine(tmp_path: Path) -> None:
    real = {
        "engine": "clamscan", "files": 34946, "infected": 0, "errors": 0, "duration_sec": 357,
        "mode": "quick", "changed_only": True, "clam_rc": 2,
        "rk_report": str(rk_log(tmp_path, ROOT_ERROR)), "rkhunter_warnings": 0, "rkhunter_rc": 1,
        "ended_epoch": 1791437544,
    }
    title, detail = format_last_scan(real)
    assert title == "No malware found"
    assert "34,946 files" in detail and "changed-files quick scan" in detail
    assert detail.endswith("rootkit check skipped (needs root)")
    assert last_scan_severity(real) == "warning"


# ------------------------------------------- the real save pipeline, end to end
def save(tmp_path: Path, rk_text: str | None) -> dict:
    env = {**os.environ, "LG_HOME": str(tmp_path / "home")}
    cmd = [sys.executable, str(ROOT / "LinuxGuardianSuite" / "scan_store.py"), "save",
           "--from-log", str(SAMPLE_CLAM), "--target", "/x", "--mode", "quick", "--clam-rc", "0"]
    if rk_text is not None:
        cmd += ["--rk-log", str(rk_log(tmp_path, rk_text)), "--rk-rc", "1"]
    subprocess.run(cmd, check=True, env=env, capture_output=True)
    return json.loads((tmp_path / "home" / "scans" / "last.json").read_text())


def test_saving_a_scan_where_rkhunter_refused_to_run(tmp_path: Path) -> None:
    data = save(tmp_path, ROOT_ERROR)
    assert data["rootkit_check"] == "needs_root"
    assert "rkhunter_warnings" not in data      # no fake "0 warnings"
    assert format_last_scan(data)[0] == "No malware found"


def test_saving_a_scan_where_rkhunter_really_ran(tmp_path: Path) -> None:
    data = save(tmp_path, REAL_RKHUNTER_LOG)
    assert data["rootkit_check"] == "ran" and data["rkhunter_warnings"] == 0
    assert format_last_scan(data)[0] == "Clean"
    warned = save(tmp_path, REAL_RKHUNTER_LOG + "  Warning: The file properties have changed:\n  Warning: another\n")
    assert warned["rootkit_check"] == "ran" and warned["rkhunter_warnings"] == 2
    assert format_last_scan(warned)[0] == "2 rootkit warnings"


def test_saving_a_scan_with_no_rkhunter_log_at_all(tmp_path: Path) -> None:
    data = save(tmp_path, None)
    assert "rootkit_check" not in data
    assert format_last_scan(data)[0] == "No malware found"

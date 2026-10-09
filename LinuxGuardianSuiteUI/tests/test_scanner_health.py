"""scanner_health: can the last scan result be trusted? (read-only, no root)."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))
sys.path.insert(0, str(ROOT / "LinuxGuardianSuiteUI"))

import scan_store  # noqa: E402
import scanner_health as sh  # noqa: E402
from linuxguardian_ui.scan_history import format_last_scan, last_scan_severity  # noqa: E402

DAY = 86400
NOW = 2_000_000_000.0


def make_db(directory: Path, name: str, age_days: float) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("x")
    os.utime(path, (NOW - age_days * DAY, NOW - age_days * DAY))
    return path


@pytest.fixture()
def clam(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_CLAMAV_DIR", str(tmp_path / "clam"))
    return tmp_path / "clam"


@pytest.mark.parametrize("age,level", [(0.1, "ok"), (2, "ok"), (2.5, "warning"), (7, "warning"), (7.5, "critical"), (200, "critical")])
def test_definition_age_levels(clam, age, level):
    make_db(clam, "daily.cld", age)
    assert sh.definitions_status(NOW)["level"] == level


def test_definitions_use_daily_not_the_old_main_file(clam):
    # main.cvd is months old on a perfectly healthy install; it must not make things look stale.
    make_db(clam, "main.cvd", 200)
    make_db(clam, "daily.cld", 0.5)
    st = sh.definitions_status(NOW)
    assert st["level"] == "ok" and st["file"] == "daily.cld"


def test_stale_daily_is_not_rescued_by_a_fresh_main(clam):
    make_db(clam, "main.cvd", 0.1)
    make_db(clam, "daily.cld", 30)
    assert sh.definitions_status(NOW)["level"] == "critical"


def test_either_daily_format_counts(clam):
    make_db(clam, "daily.cvd", 1)
    assert sh.definitions_status(NOW)["level"] == "ok"


def test_missing_definitions_are_reported_not_crashed(clam):
    st = sh.definitions_status(NOW)
    assert st["present"] is False and st["level"] == "missing" and st["age_sec"] is None


def test_rkhunter_baseline_age_and_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "home"))
    db = tmp_path / "rkhunter.dat"
    monkeypatch.setenv("LG_RKHUNTER_DB", str(db))
    assert sh.rkhunter_status(NOW)["baseline_present"] is False
    db.write_text("x")
    os.utime(db, (NOW - 5 * DAY, NOW - 5 * DAY))
    rk = sh.rkhunter_status(NOW)
    assert rk["baseline_present"] and rk["baseline_age_sec"] == 5 * DAY


def write_last(tmp_path, monkeypatch, data):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "home"))
    p = tmp_path / "home" / "scans"
    p.mkdir(parents=True)
    (p / "last.json").write_text(json.dumps(data))


@pytest.mark.parametrize("status", ["ran", "needs_root", "cancelled", "not_run"])
def test_last_check_comes_from_the_saved_scan(tmp_path, monkeypatch, status):
    write_last(tmp_path, monkeypatch, {"rootkit_check": status})
    assert sh.rkhunter_status(NOW)["last_check"] == status


def test_no_saved_scan_means_never_checked(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "nothing"))
    assert sh.rkhunter_status(NOW)["last_check"] is None


def test_corrupt_last_json_does_not_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "home"))
    (tmp_path / "home" / "scans").mkdir(parents=True)
    (tmp_path / "home" / "scans" / "last.json").write_text("{not json")
    assert sh.rkhunter_status(NOW)["last_check"] is None


def test_text_tells_the_user_how_to_turn_automatic_updates_on(clam):
    make_db(clam, "daily.cld", 1)
    health = {
        "definitions": sh.definitions_status(NOW),
        "freshclam": {"installed": True, "enabled": False, "active": False, "unit_state": "disabled"},
        "rkhunter": {"installed": True, "baseline_present": True, "baseline_age_sec": 3 * DAY, "last_check": "needs_root"},
    }
    text = sh.render_text(health)
    assert "Off" in text and "sudo systemctl enable --now clamav-freshclam" in text
    assert "skipped (needs root)" in text and "3 days ago" in text


def test_fmt_age():
    assert sh.fmt_age(None) == "unknown"
    assert sh.fmt_age(30) == "just now"
    assert sh.fmt_age(3 * 3600) == "3 hours ago"
    assert sh.fmt_age(1 * DAY) == "1 day ago"
    assert sh.fmt_age(200 * DAY) == "6 months ago"


# ------------------------------------------------ scan_store: cancelled + property changes
def test_pkexec_dismissed_with_no_log_is_cancelled_not_not_run(tmp_path):
    assert scan_store.rootkit_check_status(None, 126) == "cancelled"
    assert scan_store.rootkit_check_status(tmp_path / "gone.log", 127) == "cancelled"
    assert scan_store.rootkit_check_status(None, None) == "not_run"
    assert scan_store.rootkit_check_status(None, 1) == "not_run"


def test_property_change_count(tmp_path):
    log = tmp_path / "rk.log"
    log.write_text("  Warning: The file properties have changed:\n    File: /usr/bin/x\n"
                   "  Warning: The file properties have changed:\n  Warning: Hidden file found: /a\n")
    assert scan_store.rkhunter_property_change_count(log) == 2
    assert scan_store.rkhunter_warning_count(log) == 3
    assert scan_store.rkhunter_property_change_count(None) == 0


# ------------------------------------------------ the card
BASE = {"infected": 0, "files": 100, "duration_sec": 5, "errors": 0, "mode": "quick", "ended_epoch": 1}


def test_cancelled_is_never_clean():
    title, detail = format_last_scan({**BASE, "rootkit_check": "cancelled"})
    assert title == "No malware found" and "rootkit check cancelled" in detail
    assert last_scan_severity({**BASE, "rootkit_check": "cancelled"}) == "warning"


def test_changed_file_warnings_are_explained_but_still_shown():
    title, detail = format_last_scan({**BASE, "rootkit_check": "ran", "rkhunter_warnings": 5, "rkhunter_property_changes": 5})
    assert title == "5 rootkit warnings"           # still not "Clean"
    assert "all are changed files" in detail
    _, detail = format_last_scan({**BASE, "rootkit_check": "ran", "rkhunter_warnings": 5, "rkhunter_property_changes": 3})
    assert "3 are changed files" in detail
    _, detail = format_last_scan({**BASE, "rootkit_check": "ran", "rkhunter_warnings": 2})
    assert "changed files" not in detail           # nothing to excuse
    assert last_scan_severity({**BASE, "rootkit_check": "ran", "rkhunter_warnings": 5}) == "warning"


def _health(clam, *, active, installed=True, last="ran", age=1):
    make_db(clam, "daily.cld", age)
    return {
        "definitions": sh.definitions_status(NOW),
        "freshclam": {"installed": installed, "enabled": active, "active": active, "unit_state": "enabled" if active else "disabled"},
        "rkhunter": {"installed": True, "baseline_present": True, "baseline_age_sec": DAY, "last_check": last},
    }


def test_rows_colour_each_fact_independently(clam):
    rows = {r["key"]: r for r in sh.describe(_health(clam, active=False, last="needs_root", age=6))}
    assert rows["definitions"]["level"] == "warning"
    assert rows["auto_update"]["level"] == "warning" and rows["auto_update"]["command"] == sh.ENABLE_UPDATER_CMD
    assert rows["rootkit"]["level"] == "warning"


def test_everything_healthy_is_all_ok_and_offers_no_command(clam):
    rows = sh.describe(_health(clam, active=True, last="ran"))
    assert [r["level"] for r in rows] == ["ok", "ok", "ok"]
    assert not any("command" in r for r in rows)


def test_a_service_that_is_not_installed_gets_no_enable_command(clam):
    row = [r for r in sh.describe(_health(clam, active=False, installed=False)) if r["key"] == "auto_update"][0]
    assert "command" not in row   # `systemctl enable` would just fail


def test_the_cli_the_dashboard_calls_really_works(tmp_path, monkeypatch):
    """The UI runs `scanner_health.py --json` through scripts.run_sync; an unrecognised flag broke this once."""
    import subprocess

    make_db(tmp_path / "clam", "daily.cld", 1)
    env = {**os.environ, "LG_CLAMAV_DIR": str(tmp_path / "clam"), "LG_HOME": str(tmp_path / "h"),
           "LG_RKHUNTER_DB": str(tmp_path / "none")}
    script = ROOT / "LinuxGuardianSuite" / "scanner_health.py"
    assert os.access(script, os.X_OK)           # scripts.py executes it directly
    for flag in ("--json", "--text", "--summary"):
        out = subprocess.run([str(script), flag], capture_output=True, text=True, env=env)
        assert out.returncode == 0 and out.stdout.strip(), (flag, out.stderr)
    data = json.loads(subprocess.run([str(script), "--json"], capture_output=True, text=True, env=env).stdout)
    assert set(data) == {"definitions", "freshclam", "rkhunter"}
    assert sh.describe(data)                     # the UI's own consumer accepts it

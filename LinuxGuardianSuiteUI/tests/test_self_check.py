"""LinuxGuardian watching itself: tamper detection judged against git, permissions, damaged state, upkeep, and the sensor wiring."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import incidents  # noqa: E402
import self_check as sc  # noqa: E402
import sensors as sn  # noqa: E402
from test_sensors import DAY, at, box, sensor_events  # noqa: E402,F401  (box is a fixture)

T0 = 1_800_000_000.0


def write(p: Path, text: str, mode: int = 0o644) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    p.chmod(mode)
    return p


def make_app(root: Path) -> None:
    write(root / "LinuxGuardianSuite/sensors.py", "print('sensors')\n", 0o755)
    write(root / "LinuxGuardianSuite/utils.sh", "echo utils\n", 0o755)
    write(root / "LinuxGuardianSuiteUI/linuxguardian_ui/main.py", "print('ui')\n")
    write(root / "LinuxGuardianSuiteUI/linuxguardian_ui/pages/dash.py", "print('dash')\n")
    write(root / "LinuxGuardianSuiteUI/resources/style.css", "a{}\n")
    write(root / "LinuxGuardianSuiteUI/tests/test_x.py", "assert True\n")           # tests aren't part of the app


def git(root: Path, *args: str) -> str:
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t", HOME=str(root))
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, env=env, check=True).stdout


@pytest.fixture()
def env(tmp_path, monkeypatch):
    app = tmp_path / "app"
    make_app(app)
    lg = tmp_path / "lg"
    lg.mkdir(mode=0o700)
    lg.chmod(0o700)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    write(bindir / "systemctl", '#!/bin/sh\necho "${SC_TIMER:-enabled}"\n', 0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    monkeypatch.setenv("LG_HOME", str(lg))
    monkeypatch.setenv("LG_APP_ROOT", str(app))
    monkeypatch.setenv("LG_SELF_NOW", str(T0))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    return tmp_path


def by_id(result: dict) -> dict:
    return {c["id"]: c for c in result["checks"]}


def files_check() -> dict:
    return sc.judge_app_files()


# ------------------------------------------------------------------- app files
def test_first_run_records_a_baseline_then_everything_matches(env):
    c = files_check()
    assert c["level"] == "info" and "baseline of 5 app files" in c["text"]
    assert sc.manifest_path().is_file() and stat.S_IMODE(sc.manifest_path().stat().st_mode) == 0o600
    c = files_check()
    assert c["level"] == "ok" and "All 5 app files match" in c["text"]


def test_tests_and_bytecode_are_not_part_of_the_baseline(env):
    write(env / "app/LinuxGuardianSuite/__pycache__/x.cpython-310.pyc", "junk")
    assert set(sc.app_files()) == {"LinuxGuardianSuite/sensors.py", "LinuxGuardianSuite/utils.sh", "LinuxGuardianSuiteUI/linuxguardian_ui/main.py",
                                   "LinuxGuardianSuiteUI/linuxguardian_ui/pages/dash.py", "LinuxGuardianSuiteUI/resources/style.css"}


def test_a_modified_file_without_git_is_a_warning_until_accepted(env):
    files_check()
    write(env / "app/LinuxGuardianSuite/sensors.py", "print('changed')\n", 0o755)
    c = files_check()
    assert c["level"] == "warning" and c["paths"] == ["LinuxGuardianSuite/sensors.py"] and c["repair"] == "accept"
    assert "changed: LinuxGuardianSuite/sensors.py" in c["detail"] and "tampering" in c["text"]
    sc.apply("accept")
    assert files_check()["level"] == "ok"


def test_a_new_program_file_is_critical(env):
    files_check()
    write(env / "app/LinuxGuardianSuite/helper.py", "import os\n", 0o755)
    c = files_check()
    assert c["level"] == "critical" and "new program file" in c["text"] and c["paths"] == ["LinuxGuardianSuite/helper.py"]


def test_a_missing_file_is_reported(env):
    files_check()
    (env / "app/LinuxGuardianSuite/utils.sh").unlink()
    c = files_check()
    assert c["level"] == "warning" and "missing: LinuxGuardianSuite/utils.sh" in c["detail"]


def test_a_world_writable_changed_file_is_critical(env):
    files_check()
    write(env / "app/LinuxGuardianSuite/utils.sh", "echo evil\n", 0o777)
    c = files_check()
    assert c["level"] == "critical" and "anyone on this laptop" in c["text"]


def test_a_clean_git_update_is_information_not_an_alert(env):
    app = env / "app"
    git(app, "init", "-q")
    git(app, "add", "-A")
    git(app, "commit", "-qm", "one")
    assert files_check()["level"] == "info"                              # baseline recorded at commit one
    write(app / "LinuxGuardianSuite/sensors.py", "print('v2')\n", 0o755)
    git(app, "commit", "-qam", "two")
    c = files_check()
    assert c["level"] == "info" and "was updated" in c["text"] and c["repair"] == "accept"
    sc.apply("accept")
    assert files_check()["level"] == "ok"


def test_edits_that_are_not_committed_are_a_warning_even_with_git(env):
    app = env / "app"
    git(app, "init", "-q")
    git(app, "add", "-A")
    git(app, "commit", "-qm", "one")
    files_check()
    write(app / "LinuxGuardianSuite/sensors.py", "print('edited, not committed')\n", 0o755)
    c = files_check()
    assert c["level"] == "warning" and "uncommitted changes" in c["text"] and c["sensor_level"] == "info"


def test_a_new_commit_plus_uncommitted_edits_is_not_a_clean_update(env):
    app = env / "app"
    git(app, "init", "-q")
    git(app, "add", "-A")
    git(app, "commit", "-qm", "one")
    files_check()
    write(app / "LinuxGuardianSuite/sensors.py", "print('v2')\n", 0o755)
    git(app, "commit", "-qam", "two")
    write(app / "LinuxGuardianSuite/utils.sh", "echo sneaky\n", 0o755)         # an edit on top that nobody committed
    c = files_check()
    assert c["level"] == "warning" and "uncommitted changes" in c["text"] and c["sensor_level"] == "info"


def test_an_uncommitted_new_file_in_a_git_checkout_is_development_not_tampering(env):
    app = env / "app"
    git(app, "init", "-q")
    git(app, "add", "-A")
    git(app, "commit", "-qm", "one")
    files_check()
    write(app / "LinuxGuardianSuite/new_feature.py", "x = 1\n", 0o755)
    c = files_check()
    assert c["level"] == "warning" and c["sensor_level"] == "info" and c["dev_checkout"] is True
    assert "1 new" in c["text"] and "uncommitted" in c["text"] and "git status" in c["text"]


def test_a_dropped_file_with_no_git_history_to_explain_it_is_still_critical(env):
    files_check()
    write(env / "app/LinuxGuardianSuite/dropped.sh", "curl x | sh\n", 0o755)
    c = files_check()
    assert c["level"] == "critical" and c["sensor_level"] == "critical" and c["dev_checkout"] is False


def test_tampering_signs_stay_critical_even_in_a_git_checkout(env, monkeypatch):
    app = env / "app"
    git(app, "init", "-q")
    git(app, "add", "-A")
    git(app, "commit", "-qm", "one")
    files_check()
    write(app / "LinuxGuardianSuite/sensors.py", "print('evil')\n", 0o777)             # anyone can write to it
    c = files_check()
    assert c["level"] == "critical" and c["sensor_level"] == "critical" and "anyone on this laptop" in c["text"]
    write(app / "LinuxGuardianSuite/sensors.py", "print('evil')\n", 0o755)
    real = os.getuid()
    monkeypatch.setattr(sc.os, "getuid", lambda: real + 777)                           # owned by someone else
    assert files_check()["level"] == "critical"


def test_a_new_file_that_is_in_the_published_version_is_not_critical(env):
    app = env / "app"
    git(app, "init", "-q")
    git(app, "add", "-A")
    git(app, "commit", "-qm", "one")
    files_check()
    write(app / "LinuxGuardianSuite/new_feature.py", "x = 1\n", 0o755)
    git(app, "add", "-A")
    git(app, "commit", "-qm", "two")
    c = files_check()
    assert c["level"] == "info" and "was updated" in c["text"]


def test_a_damaged_baseline_is_never_quietly_replaced(env):
    files_check()
    sc.manifest_path().write_text("{broken")
    write(env / "app/LinuxGuardianSuite/sensors.py", "print('evil')\n", 0o755)
    c = files_check()
    assert c["level"] == "warning" and "damaged" in c["text"] and c["repair"] == "state:self_manifest"
    assert sc.manifest_path().read_text() == "{broken"                  # still not re-baselined behind your back


def test_a_damaged_baseline_can_be_restored_from_the_daily_backup(env):
    files_check()
    sc.maintain()
    good = sc.manifest_path().read_text()
    sc.manifest_path().write_text("{broken")
    sc.apply("state:self_manifest")
    assert sc.manifest_path().read_text() == good and files_check()["level"] == "ok"


# --------------------------------------------------------------- permissions
def test_app_permissions_flag_world_writable_files_and_offer_a_fix(env):
    f = env / "app/LinuxGuardianSuite/utils.sh"
    f.chmod(0o777)
    c = sc.check_app_permissions()
    assert c["level"] == "critical" and c["repair"] == "app_perms" and "LinuxGuardianSuite/utils.sh" in c["detail"][0]
    p = sc.plan("app_perms")
    assert any("777 -> 775" in s for s in p["steps"])
    assert f.stat().st_mode & 0o777 == 0o777                             # planning changed nothing
    sc.apply("app_perms")
    assert f.stat().st_mode & 0o777 == 0o775 and sc.check_app_permissions()["level"] == "ok"


def test_a_world_writable_app_folder_is_critical(env):
    (env / "app/LinuxGuardianSuite").chmod(0o777)
    c = sc.check_app_permissions()
    assert c["level"] == "critical" and "app folder" in c["text"]


def test_other_peoples_files_in_the_app_are_critical(env, monkeypatch):
    real = os.getuid()
    monkeypatch.setattr(sc.os, "getuid", lambda: real + 12345)
    assert sc.check_app_permissions()["level"] == "critical"


def test_data_folder_privacy_is_checked_and_fixed(env):
    lg = env / "lg"
    assert sc.check_data_permissions()["level"] == "ok"
    lg.chmod(0o775)
    c = sc.check_data_permissions()
    assert c["level"] == "warning" and c["repair"] == "perms" and "775 should be 700" in c["detail"][0]
    assert sc.plan("perms")["steps"][0].endswith("775 -> 700")
    sc.apply("perms")
    assert lg.stat().st_mode & 0o777 == 0o700 and sc.check_data_permissions()["level"] == "ok"


def test_a_symlinked_data_folder_is_never_chmodded(env, monkeypatch):
    real = env / "elsewhere"
    real.mkdir(mode=0o777)
    real.chmod(0o777)
    link = env / "linklg"
    link.symlink_to(real)
    monkeypatch.setenv("LG_HOME", str(link))
    assert sc.data_perm_plan() == []
    sc.apply("perms")
    assert real.stat().st_mode & 0o777 == 0o777


# ------------------------------------------------------------- state & backups
def test_damaged_state_without_a_backup_is_moved_aside_and_kept(env):
    p = write(env / "lg/state/sensors.json", "{nope", 0o600)
    c = sc.check_state()
    assert c["level"] == "warning" and c["repair"] == "state:sensors" and "no backup" in c["detail"][0]
    assert "Move the damaged" in sc.plan("state:sensors")["steps"][0]
    sc.apply("state:sensors")
    assert not p.exists() and list((env / "lg/state").glob("sensors.json.corrupt-*"))
    assert sc.check_state()["level"] == "ok"


def test_damaged_state_is_restored_from_the_newest_good_backup(env):
    p = write(env / "lg/state/sensors.json", json.dumps({"first_run": 1, "marker": "good"}), 0o600)
    sc.maintain()
    p.write_text("{garbage")
    c = sc.check_state()
    assert "a good backup from" in c["detail"][0]
    msg = sc.apply("state:sensors")
    assert "Restored" in msg and json.loads(p.read_text())["marker"] == "good" and stat.S_IMODE(p.stat().st_mode) == 0o600
    assert list((env / "lg/state").glob("sensors.json.corrupt-*"))        # the damaged copy was kept for inspection


def test_a_damaged_file_is_never_snapshotted_over_a_good_backup(env):
    p = write(env / "lg/state/sensors.json", json.dumps({"marker": "good"}), 0o600)
    sc.maintain()
    p.write_text("{garbage")
    sc.maintain()                                                         # same day: would overwrite the good snapshot if it didn't check
    b = sc.newest_backup("sensors")
    assert b and json.loads(b[0].read_text())["marker"] == "good"


def test_repairs_only_accept_known_names(env):
    for bad in ("", "rm -rf ~", "state:../../etc/passwd", "state:bogus", "perms; ls", "state:SENSORS", "accept ", "PERMS"):
        with pytest.raises(ValueError):
            sc.plan(bad)
        with pytest.raises(ValueError):
            sc.apply(bad)


# ------------------------------------------------------------------ allow-list
def test_allow_list_entries_in_tmp_or_hidden_folders_are_flagged(env):
    write(env / "lg/sensors_allow.json", json.dumps({"exe": ["/opt/vendor/", "/tmp/payload", str(env / "home/.hidden/x"), "/usr/local/bin/tool"]}))
    c = sc.check_allow_list()
    assert c["level"] == "warning" and "2 of 4" in c["text"] and "/tmp/payload" in c["detail"]
    write(env / "lg/sensors_allow.json", json.dumps({"exe": ["/opt/vendor/"]}))
    assert sc.check_allow_list()["level"] == "ok"
    (env / "lg/sensors_allow.json").unlink()
    assert sc.check_allow_list()["level"] == "ok"


# ------------------------------------------------------------------- monitoring
def test_monitoring_states(env, monkeypatch):
    monkeypatch.setenv("SC_TIMER", "disabled")
    assert sc.check_monitoring()["level"] == "info"
    monkeypatch.setenv("SC_TIMER", "enabled")
    assert sc.check_monitoring()["level"] == "warning" and "never run" in sc.check_monitoring()["text"]
    write(env / "lg/state/sensors.json", json.dumps({"last_run": T0 - 120}))
    c = sc.check_monitoring()
    assert c["level"] == "ok" and "2 minute" in c["text"]
    write(env / "lg/state/sensors.json", json.dumps({"last_run": T0 - 3 * 3600}))
    c = sc.check_monitoring()
    assert c["level"] == "warning" and "hasn't run for 180 minutes" in c["text"]


def test_space_warnings(env, monkeypatch):
    assert sc.check_space()["level"] == "ok"
    monkeypatch.setattr(sc.shutil, "disk_usage", lambda p: type("U", (), {"free": 100 * 1024 * 1024})())
    assert sc.check_space()["level"] == "warning" and "100 MB" in sc.check_space()["text"]
    monkeypatch.undo()
    monkeypatch.setenv("LG_HOME", str(env / "lg"))
    monkeypatch.setattr(sc, "BIG_LOG", 10)
    write(env / "lg/logs/big.log", "x" * 100)
    assert sc.check_space()["level"] == "warning"


# ----------------------------------------------------------------------- upkeep
def test_maintain_snapshots_rotates_the_log_and_prunes_old_snapshots(env, monkeypatch):
    write(env / "lg/state/sensors.json", "{}", 0o600)
    write(env / "lg/ai.json", "{}", 0o600)
    monkeypatch.setattr(sc, "LOG_ROTATE_AT", 10)
    write(env / "lg/logs/linuxguardian.log", "x" * 50)
    write(env / "lg/logs/linuxguardian.log.1", "older")
    old = env / "lg/backups/20260101"
    old.mkdir(parents=True)
    (old / "x").write_text("x")
    r = sc.maintain()
    assert r["backed_up"] == 2 and r["rotated"] and r["pruned"] == 1 and not old.exists()
    assert (env / "lg/logs/linuxguardian.log.1").read_text() == "x" * 50 and (env / "lg/logs/linuxguardian.log.2").read_text() == "older"
    assert not (env / "lg/logs/linuxguardian.log").exists()
    snap = next((env / "lg/backups").iterdir())
    assert stat.S_IMODE(snap.stat().st_mode) == 0o700 and stat.S_IMODE((snap / "state__sensors.json").stat().st_mode) == 0o600


def test_recent_snapshots_are_kept(env):
    write(env / "lg/state/sensors.json", "{}", 0o600)
    sc.maintain()
    assert sc.maintain()["pruned"] == 0 and len(list((env / "lg/backups").iterdir())) == 1


# ------------------------------------------------------------------- overall
def test_check_summarises_and_lists_every_area(env):
    r = sc.check()
    assert {c["id"] for c in r["checks"]} == {"app_files", "app_permissions", "data_permissions", "state", "allow_list", "monitoring", "space"}
    assert r["level"] in ("ok", "info", "warning") and ("healthy" in r["headline"] or "attention" in r["headline"])
    (env / "app/LinuxGuardianSuite/sensors.py").chmod(0o777)
    r = sc.check()
    assert r["level"] == "critical" and "serious" in r["headline"]


def test_check_works_on_the_real_install_without_writing_outside_the_data_folder(env, monkeypatch):
    monkeypatch.delenv("LG_APP_ROOT")
    r = sc.check()
    assert by_id(r)["app_files"]["level"] in ("info", "ok")
    assert sc.manifest_path().is_file() and len(sc.load_manifest()["files"]) > 40


def test_cli(env, capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["self_check.py", "--check", "--json"])
    assert sc.main() == 0 and json.loads(capsys.readouterr().out)["checks"]
    monkeypatch.setattr(sys, "argv", ["self_check.py", "--plan", "accept"])
    assert sc.main() == 0 and "trusted" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["self_check.py", "--apply", "bogus"])
    assert sc.main() == 1 and "unknown repair" in capsys.readouterr().err
    monkeypatch.setattr(sys, "argv", ["self_check.py", "--maintain"])
    assert sc.main() == 0


# ---------------------------------------------------------- sensor + incident
def test_the_sensor_reports_a_modified_app_file_once(box, monkeypatch):
    app = box / "approot"
    make_app(app)
    sn.run_once()                                                         # first run: baseline
    assert sensor_events(box) == []
    write(app / "LinuxGuardianSuite/sensors.py", "print('evil')\n", 0o755)
    at(monkeypatch, 600)
    sn.run_once()
    [e] = sensor_events(box)
    assert e["event"] == "app_modified" and e["severity"] == "warning" and e["technique"] == "T1554"
    assert str(app / "LinuxGuardianSuite/sensors.py") in e["entity"] and e["files"] == ["LinuxGuardianSuite/sensors.py"]
    at(monkeypatch, 1200)
    sn.run_once()
    assert len(sensor_events(box)) == 1                                  # the 24 h cooldown applies


def test_the_sensor_reports_a_dropped_file_as_tampering_with_its_own_story(box, monkeypatch):
    app = box / "approot"
    make_app(app)
    sn.run_once()
    write(app / "LinuxGuardianSuite/backdoor.py", "import socket\n", 0o755)
    at(monkeypatch, 600)
    sn.run_once()
    [e] = sensor_events(box)
    assert e["event"] == "app_tampered" and e["severity"] == "critical"
    [inc] = incidents.build(days=7, directory=box / "lg" / "incidents", now=time.time() + 60)
    assert inc.title == "LinuxGuardian's own files were tampered with" and inc.severity == "critical"


def test_the_sensor_stays_quiet_when_nothing_changed_and_works_with_an_empty_tree(box, monkeypatch):
    sn.run_once()
    at(monkeypatch, 4 * DAY)
    sn.run_once()
    assert sensor_events(box) == []
    assert "self" in [s["name"] for s in sn.status()["sensors"]]


def test_daily_upkeep_runs_from_the_sensors(box, monkeypatch):
    write(box / "lg/state/sensors.json", "{}", 0o600)
    sn.run_once()
    assert (box / "lg/backups").is_dir()


# ------------------------------------------------ development must not raise alarms
def init_repo(box: Path) -> Path:
    app = box / "approot"
    make_app(app)
    git(app, "init", "-q")
    git(app, "add", "-A")
    git(app, "commit", "-qm", "one")
    return app


def test_editing_the_app_in_its_git_checkout_is_a_quiet_note_not_an_incident_or_a_popup(box, monkeypatch):
    import notify_events as ne
    app = init_repo(box)
    sn.run_once()                                                        # baseline
    ne.run_send(time.time() - 100)
    write(app / "LinuxGuardianSuite/sensors.py", "print('edited')\n", 0o755)
    write(app / "LinuxGuardianSuite/brand_new.py", "x = 1\n", 0o755)
    at(monkeypatch, 600)
    sn.run_once()
    [e] = sensor_events(box)
    assert e["event"] == "app_modified" and e["severity"] == "info"
    assert incidents.build(days=7, directory=box / "lg" / "incidents", now=time.time() + 60) == []
    assert ne.run_send(time.time() + 5) == 0
    write(app / "LinuxGuardianSuite/another.py", "y = 2\n", 0o755)
    at(monkeypatch, 1200)
    sn.run_once()
    assert incidents.build(days=7, directory=box / "lg" / "incidents", now=time.time() + 60) == []      # even repeated notes never become an incident


def test_a_writable_app_file_in_a_git_checkout_is_still_a_critical_incident_and_a_popup(box, monkeypatch):
    import notify_events as ne
    app = init_repo(box)
    sn.run_once()
    ne.run_send(time.time() - 100)
    write(app / "LinuxGuardianSuite/sensors.py", "print('evil')\n", 0o777)
    at(monkeypatch, 600)
    sn.run_once()
    [e] = sensor_events(box)
    assert e["event"] == "app_tampered" and e["severity"] == "critical"
    [inc] = incidents.build(days=7, directory=box / "lg" / "incidents", now=time.time() + 60)
    assert inc.severity == "critical"
    assert ne.run_send(time.time() + 5) == 1


def test_a_tracked_file_edited_outside_git_is_still_noticed_as_information(box, monkeypatch):
    app = init_repo(box)
    sn.run_once()
    write(app / "LinuxGuardianSuite/utils.sh", "echo tampered\n", 0o755)
    at(monkeypatch, 600)
    sn.run_once()
    [e] = sensor_events(box)
    assert e["event"] == "app_modified" and e["severity"] == "info" and "utils.sh" in json.dumps(e)


def test_without_git_a_modified_file_is_still_a_warning_incident(box, monkeypatch):
    app = box / "approot"
    make_app(app)
    sn.run_once()
    write(app / "LinuxGuardianSuite/sensors.py", "print('evil')\n", 0o755)
    at(monkeypatch, 600)
    sn.run_once()
    [e] = sensor_events(box)
    assert e["event"] == "app_modified" and e["severity"] == "warning"
    assert len(incidents.build(days=7, directory=box / "lg" / "incidents", now=time.time() + 60)) == 1

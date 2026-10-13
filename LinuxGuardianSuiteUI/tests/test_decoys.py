"""Decoy files: planted safely, noticed when read/changed/deleted, quiet during our own scans, and honest about what the disk can detect."""
from __future__ import annotations

import json
import os
import re
import stat
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import decoys as dc  # noqa: E402
import incidents  # noqa: E402
import integrity  # noqa: E402
import sensors as sn  # noqa: E402
from test_sensors import at, box, sensor_events  # noqa: E402,F401  (box is a fixture)

SSH, AWS, ENV = ".ssh/old_deploy_key", ".aws/credentials.bak", ".env.production.bak"


@pytest.fixture()
def home(box):
    return box / "home"


def simulate_read(path: Path, offset_s: float = 0.0) -> None:
    """A read, independent of what this disk does with access times: the access time moves past the armed value."""
    st = os.stat(path)
    os.utime(path, ns=(int(time.time() * 1e9 + offset_s * 1e9), st.st_mtime_ns))


def events(found):
    return sorted(f["event"] for f in found)


# ------------------------------------------------------------------- creating
def test_create_plants_three_private_fake_secrets(home):
    r = dc.create()
    assert sorted(Path(p).name for p in r["created"]) == sorted(["credentials.bak", ".env.production.bak", "old_deploy_key"])
    for rel in (SSH, AWS, ENV):
        p = home / rel
        assert p.is_file() and stat.S_IMODE(p.stat().st_mode) == 0o600
    assert (home / ".aws").is_dir() and stat.S_IMODE((home / ".aws").stat().st_mode) == 0o700
    assert stat.S_IMODE(dc.state_path().stat().st_mode) == 0o600


def test_the_decoys_look_real_but_are_random_nonsense(home):
    dc.create()
    key = (home / SSH).read_text()
    assert key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----\n") and key.rstrip().endswith("-----END OPENSSH PRIVATE KEY-----")
    aws = (home / AWS).read_text()
    assert re.search(r"aws_access_key_id = AKIA[A-Z0-9]{16}\n", aws) and re.search(r"aws_secret_access_key = \S{40}\n", aws)
    env = (home / ENV).read_text()
    assert "DATABASE_URL=postgres://admin:" in env and "sk_live_" in env
    first = (home / SSH).read_text()
    dc.remove()
    dc.create()
    assert (home / SSH).read_text() != first                              # fresh random text every time


def test_create_is_idempotent_and_never_overwrites_a_real_file(home):
    (home / ".ssh").mkdir()
    real = home / SSH
    real.write_text("MY REAL KEY")
    r = dc.create()
    assert real.read_text() == "MY REAL KEY"
    assert [Path(s["path"]).name for s in r["skipped"]] == ["old_deploy_key"] and len(r["created"]) == 2
    again = dc.create()
    assert again["created"] == [] and real.read_text() == "MY REAL KEY"


def test_create_survives_a_file_appearing_at_the_last_moment(home, monkeypatch):
    (home / ".ssh").mkdir()
    (home / SSH).write_text("MY REAL KEY")
    monkeypatch.setattr(dc.os.path, "lexists", lambda p: False)           # the existence check was fooled (a race)
    r = dc.create()
    assert (home / SSH).read_text() == "MY REAL KEY" and any(s["path"].endswith("old_deploy_key") for s in r["skipped"])


def test_create_never_follows_a_symlink(home, tmp_path):
    target = tmp_path / "victim.txt"
    target.write_text("keep")
    (home / ".ssh").mkdir()
    (home / SSH).symlink_to(target)
    r = dc.create()
    assert target.read_text() == "keep" and any("already exists" in s["why"] for s in r["skipped"])


def test_status_reports_planted_decoys_and_disk_capability(home, monkeypatch):
    assert dc.status()["planted"] is False
    dc.create()
    s = dc.status()
    assert s["planted"] and len(s["items"]) == 3 and all(i["exists"] for i in s["items"])
    st = dc.load_state()
    st["atime_works"] = False
    dc.save_state(st)
    assert "only changes and deletions are noticed" in dc.status()["text"]


# ------------------------------------------------------------------- detecting
def test_untouched_decoys_stay_quiet(home):
    dc.create()
    assert dc.check() == [] and dc.check() == []


def test_a_read_is_reported_then_the_decoy_is_re_armed(home):
    dc.create()
    simulate_read(home / SSH)
    [f] = dc.check()
    assert f["event"] == "decoy_read" and f["path"] == str(home / SSH) and "private SSH key" in f["what"]
    assert dc.check() == []                                               # re-armed: the same read isn't reported twice
    simulate_read(home / SSH)
    assert events(dc.check()) == ["decoy_read"]


def test_a_real_read_is_detected_on_filesystems_that_record_it(home):
    if not dc.atime_works(home):
        pytest.skip("this filesystem doesn't update access times")
    dc.create()
    (home / AWS).read_text()
    assert events(dc.check()) == ["decoy_read"]


def test_arming_sets_the_access_time_before_the_modification_time(home):
    dc.create()
    st = os.stat(home / ENV)
    assert st.st_atime_ns == st.st_mtime_ns - dc.ARM_GAP * 10 ** 9


def test_changes_and_deletions_are_reported_once(home):
    dc.create()
    (home / ENV).write_text("tampered")
    [f] = dc.check()
    assert f["event"] == "decoy_modified" and dc.check() == []
    (home / SSH).unlink()
    assert events(dc.check()) == ["decoy_deleted"] and dc.check() == []
    (home / SSH).write_text("came back")                                   # recreated by someone: reported as a change
    assert events(dc.check()) == ["decoy_modified"]


def test_replacing_a_decoy_with_another_file_counts_as_a_change(home):
    dc.create()
    p = home / AWS
    p.unlink()
    p.write_text("[default]\n")
    assert "decoy_modified" in events(dc.check()) or "decoy_deleted" in events(dc.check())


def test_reads_during_a_linuxguardian_scan_are_ignored(home, box):
    dc.create()
    t = time.time()
    (box / "lg/scans").mkdir(parents=True, exist_ok=True)
    (box / "lg/scans/last.json").write_text(json.dumps({"started_epoch": t - 600, "ended_epoch": t + 600}))
    simulate_read(home / SSH)
    assert dc.check() == []
    (box / "lg/scans/last.json").write_text(json.dumps({"started_epoch": t - 7200, "ended_epoch": t - 6000}))
    simulate_read(home / SSH)
    assert events(dc.check()) == ["decoy_read"]


def test_reads_while_a_scan_is_running_are_ignored(home, box):
    dc.create()
    d = box / "proc/555"
    d.mkdir()
    (d / "cmdline").write_bytes(b"/usr/bin/clamscan\0-r\0/home/me\0")
    simulate_read(home / SSH)
    assert dc.scan_running() and dc.check() == []
    (d / "cmdline").write_bytes(b"/usr/bin/vim\0notes.txt\0")
    simulate_read(home / SSH)
    assert not dc.scan_running() and events(dc.check()) == ["decoy_read"]


def test_when_the_disk_does_not_record_reads_only_changes_are_noticed(home):
    dc.create()
    st = dc.load_state()
    st["atime_works"] = False
    dc.save_state(st)
    simulate_read(home / SSH)
    assert dc.check() == []
    (home / SSH).write_text("x")
    assert events(dc.check()) == ["decoy_modified"]


def test_atime_probe_cleans_up_after_itself(home, monkeypatch):
    before = set(os.listdir(home))
    dc.atime_works(home)
    assert set(os.listdir(home)) == before
    assert dc.atime_works(home / "does-not-exist") is False


# --------------------------------------------------------------------- removing
def test_remove_deletes_only_the_files_it_planted(home):
    dc.create()
    (home / AWS).unlink()
    (home / AWS).write_text("a real credentials backup you made later")
    r = dc.remove()
    assert sorted(Path(p).name for p in r["removed"]) == [".env.production.bak", "old_deploy_key"]
    assert (home / AWS).read_text() == "a real credentials backup you made later" and r["kept"] == [str(home / AWS)]
    assert dc.status()["planted"] is False


def test_remove_leaves_a_decoy_that_was_edited_even_after_the_edit_was_reported(home):
    dc.create()
    (home / ENV).write_text("the user put real data here")
    assert events(dc.check()) == ["decoy_modified"]                      # the monitor has now re-baselined it
    r = dc.remove()
    assert str(home / ENV) in r["kept"] and (home / ENV).read_text() == "the user put real data here"


# --------------------------------------------------- leaving them alone elsewhere
def test_integrity_checks_never_open_a_decoy(home, monkeypatch):
    dc.create()
    (home / ".ssh/config").write_text("Host a\n")
    monkeypatch.setenv("LG_INTEGRITY_HOME", str(home))
    files = {p.name for p in integrity.iter_files([home / ".ssh"])}
    assert files == {"config"}
    assert integrity.excluded(str(home / SSH)) and not integrity.excluded(str(home / ".ssh/config"))
    assert list(integrity.iter_files([home / SSH])) == []


def test_virus_scan_exclusions_cover_the_decoys():
    cfg = (ROOT / "LinuxGuardianSuite" / "config.sh").read_text()
    for name in (r"\.ssh/old_deploy_key", r"\.aws/credentials\.bak", r"\.env\.production\.bak"):
        assert cfg.count(name) == 2                                       # in both the quick and the full exclude lists


# ------------------------------------------------------------ sensor + incident
def test_the_sensor_reports_a_decoy_read_as_critical_with_its_own_story(box, home, monkeypatch):
    sn.run_once()
    dc.create()
    simulate_read(home / SSH)
    at(monkeypatch, 600)
    sn.run_once()
    [e] = sensor_events(box)
    assert e["event"] == "decoy_read" and e["severity"] == "critical" and e["technique"] == "T1552.001" and e["decoy"] is True
    assert "fake private SSH key" in e["message"] or "private SSH key" in e["message"]
    [inc] = incidents.build(days=7, directory=box / "lg" / "incidents", now=time.time() + 60)
    assert inc.title == "Someone opened a decoy file" and inc.severity == "critical"


def test_the_sensor_is_silent_when_no_decoys_were_planted(box, home, monkeypatch):
    sn.run_once()
    at(monkeypatch, 4 * 86400)
    sn.run_once()
    assert sensor_events(box) == []


def test_cli(home, capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["decoys.py", "--status"])
    assert dc.main() == 0 and "No decoys" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["decoys.py", "--create", "--json"])
    assert dc.main() == 0 and len(json.loads(capsys.readouterr().out)["created"]) == 3
    simulate_read(home / SSH)
    monkeypatch.setattr(sys, "argv", ["decoys.py", "--check"])
    assert dc.main() == 0 and "was just opened" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["decoys.py", "--remove"])
    assert dc.main() == 0 and "Removed 3" in capsys.readouterr().out

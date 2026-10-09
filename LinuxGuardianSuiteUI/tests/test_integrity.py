"""Integrity engine: honest classification, no self-inflicted alarms, persistence locations matter."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "LinuxGuardianSuite"
sys.path.insert(0, str(SUITE))

import events  # noqa: E402
import integrity  # noqa: E402


@pytest.fixture()
def box(tmp_path, monkeypatch):
    h = tmp_path / "home"
    (h / "Documents").mkdir(parents=True)
    (h / ".ssh").mkdir()
    (h / "Documents" / "notes.txt").write_text("one")
    (h / ".bashrc").write_text("export A=1\n")
    (h / ".ssh" / "authorized_keys").write_text("ssh-ed25519 AAAA me\n")
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    monkeypatch.setenv("LG_INTEGRITY_HOME", str(h))
    monkeypatch.setenv("LG_INTEGRITY_ROOTS", f"{h/'Documents'}:{h/'.bashrc'}:{h/'.ssh'}")
    return h


def run(mode: str, capsys) -> str:
    capsys.readouterr()
    getattr(integrity, f"do_{mode}")()
    return capsys.readouterr().out


def incidents(tmp_path: Path) -> list[dict]:
    return events.read_events(tmp_path / "lg" / "incidents")


def test_clean_check_after_init(box, capsys):
    run("init", capsys)
    assert "No changes detected" in run("check", capsys)


def test_modified_missing_and_new_are_told_apart(box, capsys, tmp_path):
    run("init", capsys)
    (box / "Documents" / "notes.txt").write_text("two")
    (box / ".bashrc").unlink()
    (box / "Documents" / "fresh.txt").write_text("x")
    out = run("check", capsys)
    assert "Modified files: 1" in out and "Missing files" in out and "New files in Documents" in out
    messages = [e["message"] for e in incidents(tmp_path)]
    assert any(m.startswith("File changed:") and "notes.txt" in m for m in messages)
    assert any(m.startswith("File missing:") and ".bashrc" in m for m in messages)
    assert not any("fresh.txt" in m for m in messages)          # a new document is information, not an alarm


def test_a_new_file_in_a_persistence_location_is_a_warning(box, capsys, tmp_path):
    run("init", capsys)
    (box / ".ssh" / "authorized_keys2").write_text("ssh-rsa BBBB attacker\n")
    out = run("check", capsys)
    assert "New files in start-up/persistence locations: 1" in out
    assert any("authorized_keys2" in e["message"] and e["severity"] == "warning" for e in incidents(tmp_path))


def test_git_internals_and_caches_are_not_watched(box, capsys):
    (box / "Documents" / "proj" / ".git" / "refs").mkdir(parents=True)
    (box / "Documents" / "proj" / ".git" / "refs" / "x").write_text("1")
    (box / "Documents" / ".cache").mkdir()
    (box / "Documents" / ".cache" / "c").write_text("1")
    run("init", capsys)
    base = integrity.read_baseline()
    assert not any("/.git/" in p or "/.cache/" in p for p in base)
    (box / "Documents" / "proj" / ".git" / "refs" / "x").write_text("2")
    assert "No changes detected" in run("check", capsys)


def test_checking_does_not_trip_the_honeypot_it_sits_next_to(box, capsys, tmp_path):
    run("init", capsys)
    hp = box / "Documents" / "Passwords_DO_NOT_OPEN" / "passwords.txt"
    assert hp.exists()
    base = integrity.read_baseline()
    assert str(hp) not in base                       # never hashed => never read by us
    old = os.stat(hp)
    # an old atime so a read would be visible even under relatime
    os.utime(hp, (old.st_mtime - 5, old.st_mtime - 5))
    run("init", capsys)
    out = run("check", capsys)
    assert "Honeypot" not in out and not any(e["category"] == "honeypot" for e in incidents(tmp_path))


def test_a_real_access_is_reported_once(box, capsys, tmp_path):
    run("init", capsys)
    hp = box / "Documents" / "Passwords_DO_NOT_OPEN" / "passwords.txt"
    st = hp.stat()
    os.utime(hp, (st.st_atime + 100, st.st_mtime))            # someone read it later
    out = run("check", capsys)
    assert "Honeypot file was read" in out
    assert "Honeypot file was read" not in run("check", capsys)   # not repeated on every check
    assert sum(1 for e in incidents(tmp_path) if e["category"] == "honeypot") == 1


def test_a_modified_honeypot_is_critical(box, capsys, tmp_path):
    run("init", capsys)
    hp = box / "Documents" / "Passwords_DO_NOT_OPEN" / "passwords.txt"
    hp.write_text("changed")
    assert "honeypot file was modified" in run("check", capsys).lower()
    assert any(e["category"] == "honeypot" and e["severity"] == "critical" for e in incidents(tmp_path))


def test_event_volume_is_capped(box, capsys, tmp_path):
    for i in range(60):
        (box / "Documents" / f"f{i}.txt").write_text("a")
    run("init", capsys)
    for i in range(60):
        (box / "Documents" / f"f{i}.txt").write_text("b")
    run("check", capsys)
    evs = incidents(tmp_path)
    assert len(evs) <= integrity.MAX_EVENTS + 1
    assert any("60 watched files" in e["message"] for e in evs)


def test_old_documents_only_baseline_is_compared_fairly(box, capsys, tmp_path):
    """A baseline from the previous version (no meta file, .git and honeypot included) must not flood 'missing'."""
    (box / "Documents" / "proj" / ".git").mkdir(parents=True)
    (box / "Documents" / "proj" / ".git" / "HEAD").write_text("ref")
    run("init", capsys)
    base = integrity.read_baseline()
    legacy = tmp_path / "lg" / "baselines" / "documents.sha256"
    lines = [f"{h}  {p}\n" for p, h in base.items() if "/Documents/" in p] + ["0" * 64 + f"  {box}/Documents/proj/.git/HEAD\n",
                                                      "1" * 64 + f"  {box}/Documents/Passwords_DO_NOT_OPEN/passwords.txt\n"]
    legacy.write_text("".join(lines))
    integrity.baseline_file().unlink()
    integrity.meta_file().unlink()
    out = run("check", capsys)
    assert "predates" in out and "Missing files" not in out and "No changes detected" in out


def test_no_baseline_is_an_error(box, capsys):
    assert integrity.do_check() == 1


def test_status_reports_age_and_size(box, capsys):
    run("init", capsys)
    st = json.loads(run("status", capsys))
    assert st["present"] and st["files"] >= 3 and st["age_sec"] < 5 and st["covers_extra_locations"]


def test_symlinks_are_not_followed(box, capsys):
    (box / "Documents" / "link").symlink_to("/etc/hostname")
    run("init", capsys)
    assert not any(p.endswith("/link") for p in integrity.read_baseline())


def test_shell_wrapper_runs_the_same_engine(box, tmp_path):
    env = {**os.environ, "LG_HOME": str(tmp_path / "lg"), "LG_INTEGRITY_HOME": str(box),
           "LG_INTEGRITY_ROOTS": f"{box/'Documents'}"}
    w = str(SUITE / "linux_watchdog.sh")
    assert subprocess.run([w, "--init"], env=env, capture_output=True).returncode == 0
    out = subprocess.run([w, "--check"], env=env, capture_output=True, text=True)
    assert out.returncode == 0 and "No changes detected" in out.stdout
    assert "LG_PROGRESS|phase=integrity" in out.stdout

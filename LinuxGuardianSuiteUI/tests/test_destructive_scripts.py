"""The two scripts that delete or kill: they must refuse dangerous input, touch only what they list, and be easy to preview.

`kill` is a shell builtin, so these tests replace it with an exported function that only LOGS what it would have signalled. A
regression can therefore never take down the test run or your desktop; the log says exactly what would have been hit.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import time
import uuid
from pathlib import Path

import pytest

SUITE = Path(__file__).resolve().parents[2] / "LinuxGuardianSuite"
PM = SUITE / "linux_process_manager.sh"
CC = SUITE / "linux_cache_cleanup.sh"


def run_pm(tmp: Path, *args: str, extra_env: dict | None = None) -> tuple[subprocess.CompletedProcess, list[str]]:
    log = tmp / "kill.log"
    log.write_text("")
    script = f'kill() {{ printf "%s\\n" "$*" >> "{log}"; return 0; }}; export -f kill; exec "{PM}" "$@"'
    env = {**os.environ, "LG_HOME": str(tmp / "lg"), **(extra_env or {})}
    r = subprocess.run(["bash", "-c", script, "pm", *args], capture_output=True, text=True, env=env, timeout=30)
    return r, [l for l in log.read_text().splitlines() if l]


def unique(prefix: str) -> str:
    """A process name that exists nowhere else on the machine, including in the command line that started this test run
    (`pgrep -f` matches ANY command line that merely contains the text)."""
    return f"{prefix}{uuid.uuid4().hex[:10]}"


def spawn(name: str, n: int = 1) -> list[subprocess.Popen]:
    return [subprocess.Popen(["bash", "-c", f"exec -a {shlex.quote(name)} sleep 120"]) for _ in range(n)]


@pytest.fixture()
def victims():
    procs: list[subprocess.Popen] = []
    yield procs
    for p in procs:
        p.kill()
        p.wait()


# ----------------------------------------------------------------------------- --kill PID
@pytest.mark.parametrize("bad", ["", "0", "1", "-1", "-9", "01", "1 2", "abc", "12abc", "$(id)", "`id`", "2;3", "--", "+5", "1e3", " "])
def test_kill_refuses_anything_that_is_not_one_ordinary_process_id(tmp_path, bad):
    r, calls = run_pm(tmp_path, "--kill", bad)
    assert calls == [], f"signalled {calls!r} for {bad!r}"
    assert r.returncode != 0 and "Refusing" in r.stdout + r.stderr


def test_kill_refuses_its_own_shell_and_parent(tmp_path):
    script = f'kill() {{ echo "$*" >> "{tmp_path}/k.log"; return 0; }}; export -f kill; exec "{PM}" --kill $PPID'
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env={**os.environ, "LG_HOME": str(tmp_path / "lg")})
    assert not (tmp_path / "k.log").exists() and "Refusing" in r.stdout + r.stderr


def test_kill_signals_exactly_the_one_process_asked_for(tmp_path, victims):
    victims += spawn("lg-victim-a")
    pid = victims[0].pid
    r, calls = run_pm(tmp_path, "--kill", str(pid))
    assert r.returncode == 0 and calls == [f"-0 {pid}", f"-TERM {pid}"] and "Sent SIGTERM" in r.stdout


def test_force_uses_sigkill_and_a_missing_process_is_an_error(tmp_path, victims):
    victims += spawn("lg-victim-b")
    _, calls = run_pm(tmp_path, "--kill", str(victims[0].pid), "--force")
    assert calls[-1] == f"-KILL {victims[0].pid}"
    # a pid that does not exist: the intercepted kill -0 says yes, so use the real check by not intercepting
    r = subprocess.run([str(PM), "--kill", "999999"], capture_output=True, text=True, env={**os.environ, "LG_HOME": str(tmp_path / "lg")})
    assert r.returncode == 1 and "No such process" in r.stdout + r.stderr


def test_a_real_kill_really_ends_a_real_victim(tmp_path, victims):
    victims += spawn("lg-victim-real")
    r = subprocess.run([str(PM), "--kill", str(victims[0].pid)], capture_output=True, text=True, env={**os.environ, "LG_HOME": str(tmp_path / "lg")})
    assert r.returncode == 0
    victims[0].wait(timeout=5)
    assert victims[0].returncode is not None


# ------------------------------------------------------------------------ --kill-name NAME
@pytest.mark.parametrize("bad", ["", " ", "a", "ab", "..", ".*", "...", "^$", "*", "- -", "---"])
def test_kill_by_name_refuses_empty_tiny_or_wildcard_only_names(tmp_path, bad):
    """`pgrep -f ""` matches nearly every process on the machine: that was a one-argument way to signal all of them."""
    r, calls = run_pm(tmp_path, "--kill-name", bad)
    assert calls == [], f"signalled {len(calls)} processes for {bad!r}"
    assert r.returncode != 0 and "Refusing" in r.stdout + r.stderr


def test_kill_by_name_without_any_name_does_nothing(tmp_path):
    r, calls = run_pm(tmp_path, "--kill-name")
    assert calls == [] and r.returncode != 0


def test_kill_by_name_signals_only_matching_processes(tmp_path, victims):
    name = unique("lgmatch")
    victims += spawn(name, 2) + spawn(unique("lgbystander"), 1)
    time.sleep(0.2)
    r, calls = run_pm(tmp_path, "--kill-name", name)
    signalled = sorted(int(c.split()[1]) for c in calls if c.startswith("-TERM"))
    assert signalled == sorted(p.pid for p in victims[:2]) and victims[2].pid not in signalled and r.returncode == 0


def test_kill_by_name_never_signals_another_copy_of_this_tool(tmp_path, victims):
    name = unique("lgself")
    victims += spawn(name, 1)
    victims += spawn(f"{PM} --kill-name {name}", 1)          # another instance of the tool, whose command line contains the name
    time.sleep(0.2)
    _, calls = run_pm(tmp_path, "--kill-name", name)
    assert [int(c.split()[1]) for c in calls if c.startswith("-TERM")] == [victims[0].pid]


def test_kill_by_name_stops_when_the_name_is_too_broad(tmp_path, victims):
    name = unique("lgcrowd")
    victims += spawn(name, 4)
    time.sleep(0.2)
    r, calls = run_pm(tmp_path, "--kill-name", name, extra_env={"LG_KILL_MAX": "3"})
    assert calls == [] and r.returncode != 0 and "matches 4 of your processes" in r.stdout + r.stderr
    r, calls = run_pm(tmp_path, "--kill-name", name, extra_env={"LG_KILL_MAX": "4"})
    assert len([c for c in calls if c.startswith("-TERM")]) == 4


def test_kill_by_name_skips_critical_system_processes(tmp_path, victims):
    name = unique("lgcritical")
    crit = spawn(name)[0]
    victims.append(crit)
    time.sleep(0.2)
    shim = tmp_path / "bin"                       # make `ps -o comm=` report a critical name for exactly that pid
    shim.mkdir()
    (shim / "ps").write_text(f'#!/bin/sh\nif [ "$2" = "comm=" ] && [ "$4" = "{crit.pid}" ]; then echo gnome-shell; else exec /bin/ps "$@"; fi\n')
    (shim / "ps").chmod(0o755)
    r, calls = run_pm(tmp_path, "--kill-name", name, extra_env={"PATH": f"{shim}:{os.environ['PATH']}"})
    assert calls == [] and "Skipped PID" in r.stdout + r.stderr and "gnome-shell" in r.stdout + r.stderr


def test_the_critical_list_matches_names_that_start_a_line(tmp_path):
    """The list wraps over several lines; names after a line break were never matched (lightdm, wpa_supplicant...)."""
    probe = tmp_path / "probe.sh"
    probe.write_text(f'''#!/usr/bin/env bash
source <(awk '/^CRITICAL_NAMES=/,/^}}/' "{PM}")
for n in systemd lightdm wpa_supplicant containerd firefox; do
  if is_critical_name "$n"; then echo "$n:yes"; else echo "$n:no"; fi
done
''')
    r = subprocess.run(["bash", str(probe)], capture_output=True, text=True)
    got = dict(l.split(":") for l in r.stdout.split())
    assert got == {"systemd": "yes", "lightdm": "yes", "wpa_supplicant": "yes", "containerd": "yes", "firefox": "no"}, r.stdout + r.stderr


def test_only_pids_and_names_are_ever_passed_to_kill():
    """Static guard: every kill in the script goes through the validated paths."""
    src = PM.read_text()
    assert src.count('kill "-$sig"') == 2 and "valid_pid" in src and 'pgrep -u "$(id -u)"' in src


# ------------------------------------------------------------------------- the cache cleaner
@pytest.fixture()
def home(tmp_path):
    h = tmp_path / "home"
    files = {
        ".cache/appone/blob": "x" * 100, ".cache/apptwo/sub/deep/blob": "y" * 50, ".cache/thumbnails/normal/a.png": "z" * 10,
        ".cache/google-chrome/Default/Cache/data_0": "c" * 20, ".mozilla/firefox/abc.default/cache2/entries/e1": "f" * 30,
        "Documents/keep.txt": "precious", ".config/appone/settings.json": "{}", ".local/share/appone/data.db": "db",
        ".cache/appone/../../Downloads/keep2.bin": "precious2",
    }
    for rel, text in files.items():
        p = (h / rel).resolve() if ".." in rel else h / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return h


def run_cc(h: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(CC), *args], capture_output=True, text=True, timeout=30,
                          env={**os.environ, "HOME": str(h), "LG_HOME": str(h / ".linuxguardian")})


def tree(h: Path) -> set[str]:
    return {str(p.relative_to(h)) for p in h.rglob("*") if not str(p.relative_to(h)).startswith(".linuxguardian")}


def test_the_default_is_a_dry_run_that_deletes_nothing(home):
    before = tree(home)
    r = run_cc(home, "--clean")
    assert "Dry run" in r.stdout + r.stderr and tree(home) == before
    r = run_cc(home, "--scan")
    assert r.returncode == 0 and tree(home) == before and "appone" in r.stdout


def test_applying_clears_only_caches_and_nothing_else(home):
    r = run_cc(home, "--clean", "--apply")
    assert r.returncode == 0
    for survivor in ("Documents/keep.txt", ".config/appone/settings.json", ".local/share/appone/data.db", "Downloads/keep2.bin"):
        assert (home / survivor).read_text() in ("precious", "{}", "db", "precious2"), survivor
    for gone in (".cache/appone/blob", ".cache/apptwo/sub/deep/blob", ".cache/thumbnails/normal/a.png", ".cache/google-chrome/Default/Cache/data_0",
                 ".mozilla/firefox/abc.default/cache2/entries/e1"):
        assert not (home / gone).exists(), gone


def test_the_cache_folders_themselves_are_kept_so_apps_dont_break(home):
    run_cc(home, "--clean", "--apply")
    assert (home / ".cache/appone").is_dir() and (home / ".cache/thumbnails").is_dir() and (home / ".mozilla/firefox/abc.default/cache2").is_dir()


def test_only_limits_the_cleaning_to_one_category(home):
    run_cc(home, "--clean", "--apply", "--only", "thumbnails")
    assert not (home / ".cache/thumbnails/normal/a.png").exists()
    assert (home / ".cache/appone/blob").exists() and (home / ".cache/google-chrome/Default/Cache/data_0").exists()


def test_symlinks_inside_a_cache_are_removed_never_followed(home, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "important.txt").write_text("do not touch")
    (home / ".cache/appone/link_to_outside").symlink_to(outside)
    (home / ".cache/appone/link_to_file").symlink_to(home / "Documents/keep.txt")
    run_cc(home, "--clean", "--apply")
    assert (outside / "important.txt").read_text() == "do not touch" and (home / "Documents/keep.txt").read_text() == "precious"
    assert not (home / ".cache/appone/link_to_outside").exists() and not os.path.lexists(home / ".cache/appone/link_to_outside")


def test_a_cache_folder_that_is_itself_a_symlink_never_empties_its_target(home, tmp_path):
    target = tmp_path / "bigdata"
    target.mkdir()
    (target / "dataset.bin").write_text("valuable")
    (home / ".cache/models").symlink_to(target)
    run_cc(home, "--clean", "--apply")
    assert (target / "dataset.bin").read_text() == "valuable"


def test_unknown_options_and_empty_homes_do_nothing_harmful(home, tmp_path):
    before = tree(home)
    r = run_cc(home, "--wipe-everything")
    assert r.returncode != 0 and tree(home) == before
    empty = tmp_path / "emptyhome"
    empty.mkdir()
    assert run_cc(empty, "--clean", "--apply").returncode == 0

"""Setuid watch: finds the right files, judges each by where it is and who owns it, and never mistakes a partial look for a removal."""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import incidents  # noqa: E402
import sensors as sn  # noqa: E402
import setuid_watch as sw  # noqa: E402
from conftest import strip_special_bits  # noqa: E402
from test_sensors import DAY, at, box, sensor_events, stub  # noqa: E402,F401  (box is a fixture)

HOUR = 3600


@pytest.fixture()
def tree(box, monkeypatch):
    """A throwaway filesystem to walk, a dpkg that can claim ownership of PKG_OWNED, and the walk pointed at it."""
    root = box / "suroots"
    stub(box / "bin", "dpkg", 'if [ -n "$PKG_OWNED" ] && [ "$3" = "$PKG_OWNED" ]; then echo "somepkg: $3"; exit 0; fi\necho no >&2; exit 1')
    monkeypatch.setenv("LG_SETUID_ROOTS", str(root))
    yield root
    strip_special_bits(root)                       # leave nothing behind that the live setuid sensor would call a critical finding in /tmp


def mk(path: Path, mode: int, text: str = "x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    return path


def info(uid=0, mode=0o4755, sha="aaaa"):
    return {"mode": mode, "uid": uid, "sha": sha}


# -------------------------------------------------------------------- scanning
def test_scan_finds_setuid_and_setgid_regular_files_only(tree):
    mk(tree / "bin/su", 0o4755)
    mk(tree / "bin/wall", 0o2755)
    mk(tree / "bin/ls", 0o755)
    mk(tree / "bin/both", 0o6755)
    (tree / "bin/link").symlink_to(tree / "bin/su")
    d = tree / "setuiddir"
    d.mkdir()
    d.chmod(0o2755)
    found, complete = sw.scan()
    assert complete and sorted(Path(p).name for p in found) == ["both", "su", "wall"]
    assert found[str(tree / "bin/su")]["mode"] == 0o4755 and len(found[str(tree / "bin/su")]["sha"]) == 20


def test_scan_ignores_special_files_that_carry_the_bit(tree):
    (tree / "bin").mkdir()
    fifo = tree / "bin/pipe"
    os.mkfifo(fifo)
    fifo.chmod(0o4755)
    mk(tree / "bin/real", 0o4755)
    found, _ = sw.scan()
    assert [Path(p).name for p in found] == ["real"]


def test_scan_skips_caches_and_big_harmless_folders(tree):
    for name in (".cache", "node_modules", ".git", ".cargo", "snap"):
        mk(tree / "home/me" / name / "x/evil", 0o4755)
    mk(tree / "home/me/Downloads/evil", 0o4755)
    found, _ = sw.scan()
    assert [Path(p).name for p in found] == ["evil"] and "Downloads" in next(iter(found))


def test_scan_stays_on_one_filesystem(tree, monkeypatch):
    mk(tree / "here/su", 0o4755)
    mk(tree / "mounted/su", 0o4755)
    real = os.lstat
    other = tree / "mounted"

    def fake(path, *a, **k):
        st = real(path, *a, **k)
        if str(path) == str(other):
            vals = list(st)
            vals[2] = st.st_dev + 1                                     # a different device number
            return os.stat_result(vals)
        return st

    monkeypatch.setattr(sw.os, "lstat", fake)
    found, _ = sw.scan()
    assert [Path(p).parent.name for p in found] == ["here"]


def test_scan_gives_up_at_the_deadline_and_says_it_is_partial(tree):
    mk(tree / "bin/su", 0o4755)
    found, complete = sw.scan(deadline=time.monotonic() - 1)
    assert complete is False


def test_roots_resolve_symlinks_drop_duplicates_and_missing_folders(tmp_path, monkeypatch):
    real = tmp_path / "usr"
    (real / "bin").mkdir(parents=True)
    (tmp_path / "bin").symlink_to(real / "bin")
    monkeypatch.setenv("LG_SETUID_ROOTS", f"{real}/bin:{tmp_path}/bin:{tmp_path}/missing:")
    assert sw.roots() == [str(real / "bin")]
    monkeypatch.delenv("LG_SETUID_ROOTS")
    assert all(os.path.isdir(r) for r in sw.roots()) and len(sw.roots()) == len(set(sw.roots()))


# ------------------------------------------------------------------- judging
def test_the_first_look_learns_and_removals_are_ignored():
    assert sw.diff(None, {"/tmp/evil": info()}) == []
    assert sw.diff({"/usr/bin/su": info()}, {}) == []


def test_new_programs_in_unsafe_places_are_critical_even_if_root_owned():
    for place in ("/tmp/x", "/var/tmp/x", "/dev/shm/x", "/home/me/x", "/root/x"):
        [f] = sw.diff({}, {place: info(uid=0)})
        assert f["severity"] == "critical" and f["event"] == "setuid_new" and f["technique"] == "T1548.001" and place in f["message"], place


def test_new_programs_in_system_folders_depend_on_who_installed_them(monkeypatch):
    [f] = sw.diff({}, {"/usr/local/bin/mytool": info()})
    assert f["severity"] == "warning" and "no package owns it" in f["message"]
    monkeypatch.setattr(sw, "package_owner", lambda p: "sudo")
    [g] = sw.diff({}, {"/usr/bin/sudo": info()})
    assert g["severity"] == "info" and "installed by the package sudo" in g["message"]


def test_an_unexpected_owner_is_critical_unless_a_package_explains_it(monkeypatch):
    [f] = sw.diff({}, {"/usr/local/bin/x": info(uid=1000)})
    assert f["severity"] == "critical" and "unexpected owner" in f["message"] and "user id 1000" in f["message"]
    monkeypatch.setattr(sw, "package_owner", lambda p: "at")
    [g] = sw.diff({}, {"/usr/bin/at": info(uid=1, mode=0o6755)})                  # at is legitimately setuid daemon
    assert g["severity"] == "info"


def test_a_changed_setuid_program_is_a_warning_or_an_update(monkeypatch):
    old, new = {"/usr/bin/su": info(sha="aaaa")}, {"/usr/bin/su": info(sha="bbbb")}
    [f] = sw.diff(old, new)
    assert f["event"] == "setuid_changed" and f["severity"] == "warning" and "no package explains it" in f["message"]
    monkeypatch.setattr(sw, "package_owner", lambda p: "util-linux")
    [g] = sw.diff(old, new)
    assert g["severity"] == "info" and "probably an update" in g["message"]
    assert sw.diff(old, old) == []


def test_allow_listed_paths_are_skipped_like_other_sensors():
    new = {"/home/me/nvidia/rootfs/usr/bin/su": info(), "/home/me/other/x": info()}
    found = sw.diff({}, new, allow=["/home/me/nvidia/"])
    assert [f["entity"][0] for f in found] == ["/home/me/other/x"]
    assert sw.diff({}, {"/tmp/x": info()}, allow=["/tmp/x"]) == []


def test_descriptions_are_plain():
    assert sw.describe({"mode": 0o6755, "uid": 0}) == "setuid/setgid, owned by root"
    assert sw.describe({"mode": 0o2755, "uid": 33}) == "setgid, owned by user id 33"


# ----------------------------------------------------------------------- run
def test_run_learns_then_reports_only_new_programs_and_only_when_due(tree, monkeypatch):
    mk(tree / "bin/su", 0o4755)
    t = time.time()
    monkeypatch.setenv("LG_SETUID_NOW", str(t))
    state: dict = {}
    assert sw.run(state) == [] and len(state["setuid"]["files"]) == 1
    mk(tree / "tmp/rootsh", 0o4755)
    monkeypatch.setenv("LG_SETUID_NOW", str(t + HOUR))
    calls = []
    real = sw.scan
    monkeypatch.setattr(sw, "scan", lambda *a, **k: calls.append(1) or real(*a, **k))
    assert sw.run(state) == [] and calls == []                                    # not due for six hours: the disk isn't walked
    monkeypatch.setenv("LG_SETUID_NOW", str(t + 7 * HOUR))
    [f] = sw.run(state)
    assert f["event"] == "setuid_new" and f["severity"] == "critical" and "rootsh" in f["message"] and calls == [1]
    monkeypatch.setenv("LG_SETUID_NOW", str(t + 14 * HOUR))
    assert sw.run(state) == []                                                    # reported once: it is part of the baseline now


def test_a_partial_look_never_counts_as_removals_or_new_arrivals(tree, monkeypatch):
    a = mk(tree / "bin/a", 0o4755)
    b = mk(tree / "bin/b", 0o4755)
    t = time.time()
    monkeypatch.setenv("LG_SETUID_NOW", str(t))
    state: dict = {}
    sw.run(state)
    real = sw.scan
    monkeypatch.setattr(sw, "scan", lambda *a_, **k: ({str(a): real()[0][str(a)]}, False))     # ran out of time after finding only `a`
    monkeypatch.setenv("LG_SETUID_NOW", str(t + 7 * HOUR))
    assert sw.run(state) == [] and set(state["setuid"]["files"]) == {str(a), str(b)} and state["setuid"]["complete"] is False
    monkeypatch.setattr(sw, "scan", real)
    monkeypatch.setenv("LG_SETUID_NOW", str(t + 14 * HOUR))
    assert sw.run(state) == [] and state["setuid"]["complete"] is True           # b reappearing is not 'new'


def test_a_modified_setuid_file_is_found_by_its_hash(tree, monkeypatch):
    f = mk(tree / "bin/su", 0o4755, "original")
    t = time.time()
    monkeypatch.setenv("LG_SETUID_NOW", str(t))
    state: dict = {}
    sw.run(state)
    f.write_text("backdoored")
    f.chmod(0o4755)
    monkeypatch.setenv("LG_SETUID_NOW", str(t + 7 * HOUR))
    [x] = sw.run(state)
    assert x["event"] == "setuid_changed"


# ------------------------------------------------------- sensor + incidents + cli
def test_the_sensor_flags_a_dropped_setuid_shell_with_its_own_story(box, tree, monkeypatch):
    mk(tree / "bin/su", 0o4755)
    sn.run_once()
    assert sensor_events(box) == []
    mk(tree / "tmp/.hidden-sh", 0o4755)
    at(monkeypatch, 7 * HOUR)
    sn.run_once()
    [e] = sensor_events(box)
    assert e["event"] == "setuid_new" and e["severity"] == "critical" and e["technique"] == "T1548.001" and e["stage"] == "privilege"
    [inc] = incidents.build(days=7, directory=box / "lg" / "incidents", now=time.time() + 60)
    assert inc.title == "A program that runs with elevated rights appeared" and inc.severity == "critical"


def test_the_sensor_honours_the_allow_list(box, tree, monkeypatch):
    mk(tree / "bin/su", 0o4755)
    sn.run_once()
    sn.allow_path_entry(str(tree / "vendor") + "/")
    mk(tree / "vendor/helper", 0o4755)
    at(monkeypatch, 7 * HOUR)
    sn.run_once()
    assert sensor_events(box) == []


def test_cli_check_and_list(box, tree, capsys, monkeypatch):
    mk(tree / "bin/su", 0o4755)
    monkeypatch.setattr(sys, "argv", ["setuid_watch.py", "--list"])
    assert sw.main() == 0 and "No look has been taken" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["setuid_watch.py", "--check"])
    assert sw.main() == 0 and "First look: recorded 1" in capsys.readouterr().out
    mk(tree / "tmp/x", 0o4755)
    assert sw.main() == 0 and "[critical]" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["setuid_watch.py", "--list"])
    assert sw.main() == 0 and "setuid, owned by" in capsys.readouterr().out

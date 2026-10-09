"""The baseline is only offered for refresh when every warning is vouched for by an Ubuntu package."""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import rkhunter_baseline as rb  # noqa: E402

HEAD = ("[ Rootkit Hunter version 1.4.6 ]\n\nChecking system commands...\n\n"
        + "    /usr/bin/ok%d                                  [ OK ]\n" * 1 % 1
        + "  Performing 'shared libraries' checks\n    Checking for preloading variables    [ None found ]\n" * 12)


def log(tmp: Path, warned: list[str], suspect: int | None = None, extra: str = "", rc_ok: bool = True) -> Path:
    body = HEAD + "".join(f"    {p}                                  [ Warning ]\n" for p in warned)
    body += (f"\nSystem checks summary\n=====================\n\nFile properties checks...\n    Files checked: 142\n"
             f"    Suspect files: {len(warned) if suspect is None else suspect}\n\nRootkit checks...\n    Rootkits checked : 497\n"
             f"    Possible rootkits: 0\n") + extra
    if warned or extra:
        body += "\nOne or more warnings have been found while checking the system.\n"
    path = tmp / "rk.log"
    path.write_text(body)
    return path


@pytest.fixture()
def dpkg(tmp_path, monkeypatch):
    """A fake dpkg: OWNERS='path=pkg;...' for -S, MODIFIED='path;...' for --verify."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "dpkg"
    stub.write_text('''#!/usr/bin/env python3
import os, sys
a = sys.argv[1:]
if a[0] == "-S":
    owners = dict(x.split("=") for x in os.environ.get("OWNERS", "").split(";") if x)
    for p in a[2:]:
        print(f"{owners[p]}: {p}") if p in owners else print(f"dpkg-query: no path found matching pattern {p}", file=sys.stderr)
    sys.exit(0 if all(p in owners for p in a[2:]) else 1)
if a[0] == "--verify":
    for p in os.environ.get("MODIFIED", "").split(";"):
        if p: print(f"??5??????   {p}")
    if os.environ.get("VERIFY_ERR"): print("dpkg: warning: unable to open /x: Permission denied", file=sys.stderr)
    sys.exit(0)
''')
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    monkeypatch.setenv("LG_HOME", str(tmp_path / "home"))
    return monkeypatch


def test_everything_matches_its_package_is_safe(tmp_path, dpkg):
    dpkg.setenv("OWNERS", "/usr/bin/curl=curl;/usr/bin/awk=mawk")
    r = rb.analyze(log(tmp_path, ["/usr/bin/curl", "/usr/bin/awk"]))
    assert r["safe_to_refresh"] and r["explained"] == 2 and r["unexplained"] == 0


def test_a_file_that_differs_from_its_package_blocks_the_refresh(tmp_path, dpkg):
    dpkg.setenv("OWNERS", "/usr/bin/curl=curl;/usr/bin/awk=mawk")
    dpkg.setenv("MODIFIED", "/usr/bin/awk")
    r = rb.analyze(log(tmp_path, ["/usr/bin/curl", "/usr/bin/awk"]))
    assert not r["safe_to_refresh"] and r["unexplained"] == 1
    assert [f["path"] for f in r["files"] if not f["explained"]] == ["/usr/bin/awk"]
    assert "NOT explained" in r["reason"]


def test_a_file_no_package_owns_blocks_the_refresh(tmp_path, dpkg):
    dpkg.setenv("OWNERS", "/usr/bin/curl=curl")
    r = rb.analyze(log(tmp_path, ["/usr/bin/curl", "/usr/local/bin/implant"]))
    assert not r["safe_to_refresh"]
    row = [f for f in r["files"] if f["path"] == "/usr/local/bin/implant"][0]
    assert not row["explained"] and "not owned" in row["why"]


def test_unverifiable_files_are_not_treated_as_fine(tmp_path, dpkg):
    dpkg.setenv("OWNERS", "/usr/bin/curl=curl")
    dpkg.setenv("VERIFY_ERR", "1")          # dpkg couldn't read some files
    assert not rb.analyze(log(tmp_path, ["/usr/bin/curl"]))["safe_to_refresh"]


def test_other_warnings_block_even_if_every_file_is_explained(tmp_path, dpkg):
    dpkg.setenv("OWNERS", "/usr/bin/curl=curl")
    r = rb.analyze(log(tmp_path, ["/usr/bin/curl"], extra="    Checking for hidden files    [ Warning ]\n"))
    assert not r["safe_to_refresh"] and r["other_warnings"] >= 1


def test_a_count_that_does_not_add_up_blocks(tmp_path, dpkg):
    dpkg.setenv("OWNERS", "/usr/bin/curl=curl")
    # summary says 5 suspect files, but only one could be identified: the rest are unknown
    r = rb.analyze(log(tmp_path, ["/usr/bin/curl"], suspect=5))
    assert not r["safe_to_refresh"] and r["other_warnings"] == 4


def test_no_warnings_means_nothing_to_refresh(tmp_path, dpkg):
    r = rb.analyze(log(tmp_path, []))
    assert r["ok"] and not r["safe_to_refresh"] and "nothing to refresh" in r["reason"]


def test_missing_or_skipped_scan_is_refused(tmp_path, dpkg):
    assert not rb.analyze(None)["ok"]
    skipped = tmp_path / "rk.log"
    skipped.write_text("You must be the root user to run this program.\n")
    r = rb.analyze(skipped)
    assert not r["ok"] and "didn't run" in r["reason"]


def test_log_style_warnings_are_understood_too(tmp_path, dpkg):
    dpkg.setenv("OWNERS", "/usr/bin/curl=curl")
    text = HEAD + "  Warning: The file properties have changed:\n         File: /usr/bin/curl\n         Current hash: a\n" \
        "\nSystem checks summary\n    Suspect files: 1\n    Possible rootkits: 0\n"
    p = tmp_path / "rk.log"
    p.write_text(text)
    assert rb.analyze(p)["safe_to_refresh"]

"""Parsing and classification for the Updates feature (update_inventory.py)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "LinuxGuardianSuite"))

from update_inventory import (  # noqa: E402
    SECURITY,
    SNAP,
    STANDARD,
    THIRD_PARTY,
    classify_origin,
    counts,
    fmt_age,
    parse_apt_simulation,
    parse_snap_refresh,
)

# Trimmed from real `apt-get -s upgrade` output. The libkrb5 lines carry
# trailing "[...]" dependency groups after the closing paren — a parser that
# anchors at the end of the line silently drops them.
APT_SAMPLE = """\
NOTE: This is only a simulation!
Reading package lists...
Calculating upgrade...
The following packages have been kept back:
  libnvidia-cfg1-595 libnvidia-common-595
  nvidia-driver-595-open
The following packages will be upgraded:
  sudo libkrb5-3 libaudit1
Inst sudo [1.9.9-1ubuntu2.6] (1.9.9-1ubuntu2.7 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Inst libaudit1 [1:3.0.7-1build1] (1:3.0.7-1ubuntu0.1 Ubuntu:22.04/jammy-updates [amd64])
Inst libkrb5-3 [1.19.2-2ubuntu0.8] (1.19.2-2ubuntu0.10 Ubuntu:22.04/jammy-updates [amd64]) [libkrb5-3:amd64 on libkrb5-3:i386] [libgssapi-krb5-2:amd64 libkrb5-3:i386 ]
Inst libkrb5-3:i386 [1.19.2-2ubuntu0.8] (1.19.2-2ubuntu0.10 Ubuntu:22.04/jammy-updates [i386]) [libgssapi-krb5-2:amd64 ]
Inst cursor [3.22.12-1790400601] (3.23.23-1791166813 downloads.cursor.com [amd64])
Inst claude-desktop [2.9939.4] (2.26454.2 Anthropic:stable [amd64])
Conf sudo (1.9.9-1ubuntu2.7 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
"""

SNAP_SAMPLE = """\
Name           Version                         Rev    Size    Publisher    Notes
code           2a59476c                        268    555MB   vscode**     classic
firefox        157.0.1-1                       9036   275MB   mozilla**    -
snapd          2.77.1                          28254  46.9MB  canonical**  snapd
"""


def test_classify_origin() -> None:
    assert classify_origin("Ubuntu:22.04/jammy-security") == SECURITY
    # Security wins when the same candidate is also in -updates.
    assert classify_origin("Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security") == SECURITY
    assert classify_origin("UbuntuESM:22.04/jammy-infra-security") == SECURITY
    assert classify_origin("Ubuntu:22.04/jammy-updates") == STANDARD
    # Anything not from Ubuntu came from a repo the user/an installer added.
    for origin in ("downloads.cursor.com", "Anthropic:stable", "stable", "Tailscale:pkgs.tailscale.com"):
        assert classify_origin(origin) == THIRD_PARTY, origin


def test_parse_apt_keeps_lines_with_trailing_dependency_groups() -> None:
    pkgs, _ = parse_apt_simulation(APT_SAMPLE)
    names = [p["name"] for p in pkgs]
    assert "libkrb5-3" in names and "libkrb5-3:i386" in names
    # `Conf` lines repeat packages and must not be double counted.
    assert names.count("sudo") == 1
    assert len(pkgs) == 6


def test_parse_apt_fields_and_categories() -> None:
    pkgs, _ = parse_apt_simulation(APT_SAMPLE)
    by_name = {p["name"]: p for p in pkgs}
    sudo = by_name["sudo"]
    assert (sudo["installed"], sudo["candidate"], sudo["arch"]) == ("1.9.9-1ubuntu2.6", "1.9.9-1ubuntu2.7", "amd64")
    assert sudo["category"] == SECURITY
    assert by_name["libaudit1"]["category"] == STANDARD
    assert by_name["cursor"]["category"] == THIRD_PARTY
    assert by_name["claude-desktop"]["category"] == THIRD_PARTY
    assert counts(pkgs) == {SECURITY: 1, STANDARD: 3, THIRD_PARTY: 2, SNAP: 0}


def test_parse_apt_kept_back_stops_at_next_section() -> None:
    _, kept = parse_apt_simulation(APT_SAMPLE)
    assert kept == ["libnvidia-cfg1-595", "libnvidia-common-595", "nvidia-driver-595-open"]
    # Names from the "will be upgraded" list that follows must not leak in.
    assert "sudo" not in kept


def test_parse_apt_empty_and_garbage() -> None:
    assert parse_apt_simulation("") == ([], [])
    assert parse_apt_simulation("E: Could not open lock file\nsomething odd\n") == ([], [])


def test_parse_snap_refresh() -> None:
    pkgs = parse_snap_refresh(SNAP_SAMPLE)
    assert [p["name"] for p in pkgs] == ["code", "firefox", "snapd"]
    code = pkgs[0]
    assert code["candidate"] == "2a59476c" and code["rev"] == "268"
    assert code["origin"] == "vscode"  # verified-publisher "**" marker stripped
    assert code["notes"] == "classic"
    assert all(p["category"] == SNAP for p in pkgs)


def test_parse_snap_refresh_nothing_pending() -> None:
    # `snap refresh --list` prints only to stderr when up to date, so stdout is empty.
    assert parse_snap_refresh("") == []


def test_fmt_age() -> None:
    assert fmt_age(None) == "unknown"
    assert fmt_age(30) == "just now"
    assert fmt_age(10 * 60) == "10m ago"
    assert fmt_age(5 * 3600) == "5h ago"
    assert fmt_age(4 * 86400) == "4d ago"

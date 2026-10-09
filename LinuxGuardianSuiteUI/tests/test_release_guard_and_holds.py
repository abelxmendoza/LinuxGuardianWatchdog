"""Release guard (never mix Ubuntu releases) and pinned stacks (apt-mark hold)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "LinuxGuardianSuite"))

import update_inventory as inv  # noqa: E402

# --------------------------------------------------------------------------
# Source parsing
# --------------------------------------------------------------------------
ONE_LINE = """\
# a comment
deb http://us.archive.ubuntu.com/ubuntu/ jammy main restricted
deb [arch=amd64 signed-by=/usr/share/keyrings/x.gpg] http://packages.osrfoundation.org/gazebo/ubuntu-stable jammy main
deb [ arch=amd64 signed-by=/k.gpg ] https://pkgs.tailscale.com/stable/ubuntu jammy main
deb-src http://us.archive.ubuntu.com/ubuntu/ jammy-updates main   # trailing comment
deb [signed-by=/k.gpg] file:///var/l4t-cuda-repo-ubuntu2204-12-6-local /
"""

DEB822 = """\
### THIS FILE IS AUTOMATICALLY CONFIGURED ###
Types: deb
URIs: https://downloads.cursor.com/aptrepo
Suites: stable
Components: main

Types: deb deb-src
URIs: http://packages.ros.org/ros2/ubuntu
Suites: jammy
Components: main
Signed-By:  -----BEGIN PGP PUBLIC KEY BLOCK-----
 .
 mQINBFzvJpYBEADY8l1YvO7iYW5gUESyzsTGnMvVUmlV3XarBaJz9bGRmgPXh7jc
 -----END PGP PUBLIC KEY BLOCK-----

Types: deb
URIs: http://archive.ubuntu.com/ubuntu
Suites: jammy jammy-updates
Components: main

Types: deb
URIs: http://old.example.com/ubuntu
Suites: focal
Enabled: no
"""


def test_parse_one_line_handles_options_comments_and_flat_repos() -> None:
    entries = inv.parse_apt_sources(ONE_LINE, deb822=False)
    uris = [(e["uri"], e["suites"]) for e in entries]
    assert ("http://us.archive.ubuntu.com/ubuntu/", ["jammy"]) in uris
    assert ("https://pkgs.tailscale.com/stable/ubuntu", ["jammy"]) in uris  # spaces inside [ ... ]
    assert ("http://us.archive.ubuntu.com/ubuntu/", ["jammy-updates"]) in uris  # deb-src + trailing comment
    assert ("file:///var/l4t-cuda-repo-ubuntu2204-12-6-local", ["/"]) in uris
    assert len(entries) == 5


def test_parse_deb822_multi_suites_key_blocks_and_enabled_no() -> None:
    entries = inv.parse_apt_sources(DEB822, deb822=True)
    by_uri = {e["uri"]: e["suites"] for e in entries}
    assert by_uri["https://downloads.cursor.com/aptrepo"] == ["stable"]
    assert by_uri["http://packages.ros.org/ros2/ubuntu"] == ["jammy"]  # armored key didn't confuse it
    assert by_uri["http://archive.ubuntu.com/ubuntu"] == ["jammy", "jammy-updates"]
    assert "http://old.example.com/ubuntu" not in by_uri  # Enabled: no


def test_read_apt_sources_reads_both_formats_and_ignores_leftovers(tmp_path: Path) -> None:
    (tmp_path / "sources.list").write_text("deb http://archive.ubuntu.com/ubuntu jammy main\n")
    d = tmp_path / "sources.list.d"
    d.mkdir()
    (d / "ros2.sources").write_text("Types: deb\nURIs: http://packages.ros.org/ros2/ubuntu\nSuites: jammy\n")
    (d / "vendor.list").write_text("deb https://v.example.com/apt jammy main\n")
    # apt itself ignores these; so must we, or old backups would raise false alarms.
    (d / "old.list.save").write_text("deb http://archive.ubuntu.com/ubuntu noble main\n")
    (d / "x.distUpgrade").write_text("deb http://archive.ubuntu.com/ubuntu noble main\n")
    files = sorted(e["file"] for e in inv.read_apt_sources(tmp_path))
    assert files == ["ros2.sources", "sources.list", "vendor.list"]


# --------------------------------------------------------------------------
# Release guard
# --------------------------------------------------------------------------
def entry(uri: str, suite: str, file: str = "x.list") -> dict:
    return {"uri": uri, "suites": [suite], "file": file}


@pytest.mark.parametrize(
    "uri,suite",
    [
        ("http://us.archive.ubuntu.com/ubuntu/", "jammy"),
        ("http://us.archive.ubuntu.com/ubuntu/", "jammy-updates"),
        ("http://security.ubuntu.com/ubuntu", "jammy-security"),
        ("http://us.archive.ubuntu.com/ubuntu/", "jammy-backports"),
        ("https://ppa.launchpadcontent.net/ubuntu-toolchain-r/test/ubuntu", "jammy"),
        ("https://pkgs.tailscale.com/stable/ubuntu", "jammy"),
        ("https://downloads.cursor.com/aptrepo", "stable"),  # vendor channel, not a release
        ("https://apt.foxglove.dev", "stable"),
        ("file:///var/l4t-cuda-repo-ubuntu2204-12-6-local", "/"),
        ("https://nvidia.github.io/libnvidia-container/stable/deb/amd64", "/"),
    ],
)
def test_sources_for_this_release_are_fine(uri: str, suite: str) -> None:
    assert inv.foreign_sources([entry(uri, suite)], "jammy") == []


@pytest.mark.parametrize(
    "uri,suite",
    [
        ("http://us.archive.ubuntu.com/ubuntu/", "noble"),
        ("http://us.archive.ubuntu.com/ubuntu/", "noble-updates"),
        ("http://security.ubuntu.com/ubuntu", "noble-security"),
        # A release name this list has never heard of is still caught on an Ubuntu host.
        ("http://archive.ubuntu.com/ubuntu", "someFutureRelease"),
        ("https://vendor.example.com/apt", "noble"),  # a vendor repo built for another release
        ("https://apt.postgresql.org/pub/repos/apt", "focal-pgdg"),
    ],
)
def test_sources_for_another_release_are_flagged(uri: str, suite: str) -> None:
    problems = inv.foreign_sources([entry(uri, suite)], "jammy")
    assert len(problems) == 1
    assert "jammy" in problems[0]


def test_foreign_source_message_names_the_file_and_host() -> None:
    [msg] = inv.foreign_sources([entry("http://archive.ubuntu.com/ubuntu", "noble", "ubuntu.sources")], "jammy")
    assert "archive.ubuntu.com" in msg and "ubuntu.sources" in msg and "'noble'" in msg


def pkg(name: str, origin: str, manager: str = "apt") -> dict:
    return {"name": name, "origin": origin, "manager": manager, "category": "x"}


def test_foreign_release_packages() -> None:
    ok = [
        pkg("sudo", "Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security"),
        pkg("libfoo", "UbuntuESM:22.04/jammy-infra-security"),
        pkg("cursor", "downloads.cursor.com"),  # third party: not judged by origin text
        pkg("firefox", "mozilla", manager="snap"),
    ]
    assert inv.foreign_release_packages(ok, "jammy") == []
    bad = [pkg("libc6", "Ubuntu:24.04/noble-updates")]
    [msg] = inv.foreign_release_packages(bad, "jammy")
    assert "libc6" in msg and "noble-updates" in msg


def test_release_guard_ok_and_blocked() -> None:
    good = inv.release_guard("jammy", [entry("http://archive.ubuntu.com/ubuntu", "jammy")], [])
    assert good["ok"] and good["problems"] == [] and good["codename"] == "jammy"
    bad = inv.release_guard("jammy", [entry("http://archive.ubuntu.com/ubuntu", "noble")], [])
    assert not bad["ok"] and len(bad["problems"]) == 1


def test_release_guard_fails_closed_when_release_is_unknown() -> None:
    guard = inv.release_guard("", [], [])
    assert not guard["ok"]
    assert "determine" in guard["problems"][0]


def test_release_guard_not_applicable_without_apt() -> None:
    assert inv.release_guard("fedora", [], [], applicable=False)["ok"]


def test_release_guard_caps_a_long_problem_list() -> None:
    entries = [entry(f"http://h{i}.ubuntu.com/ubuntu", "noble") for i in range(10)]
    guard = inv.release_guard("jammy", entries, [])
    assert not guard["ok"]
    assert len(guard["problems"]) == 7 and guard["problems"][-1] == "...and 4 more."


def test_os_release_prefers_ubuntu_codename(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = tmp_path / "os-release"
    f.write_text('NAME="Linux Mint"\nVERSION_CODENAME=vera\nUBUNTU_CODENAME=jammy\n')
    monkeypatch.setenv("LG_OS_RELEASE_FILE", str(f))
    assert inv.current_codename() == "jammy"
    f.write_text('PRETTY_NAME="Ubuntu 22.04.5 LTS"\nVERSION_CODENAME=jammy\n')
    assert inv.current_codename() == "jammy"
    monkeypatch.setenv("LG_OS_RELEASE_FILE", str(tmp_path / "missing"))
    assert inv.current_codename() == ""


def test_run_guard_end_to_end_with_fixtures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    osr = tmp_path / "os-release"
    osr.write_text("VERSION_CODENAME=jammy\nUBUNTU_CODENAME=jammy\n")
    apt = tmp_path / "apt"
    (apt / "sources.list.d").mkdir(parents=True)
    (apt / "sources.list").write_text("deb http://archive.ubuntu.com/ubuntu jammy main\n")
    monkeypatch.setenv("LG_OS_RELEASE_FILE", str(osr))
    monkeypatch.setenv("LG_APT_ROOT", str(apt))
    monkeypatch.setattr(inv, "_run", lambda *a, **k: "")  # no real apt-get

    assert inv.run_guard() == 0
    assert "OK" in capsys.readouterr().out

    (apt / "sources.list.d" / "oops.list").write_text("deb http://archive.ubuntu.com/ubuntu noble main\n")
    assert inv.run_guard() == 3
    out = capsys.readouterr().out
    assert "BLOCKED" in out and "noble" in out


# --------------------------------------------------------------------------
# Pinned stacks
# --------------------------------------------------------------------------
def group_pattern(gid: str):
    return inv.group_by_id(gid)["pattern"]


def test_package_name_validation() -> None:
    for good in ("bash", "libstdc++6", "g++", "libnvidia-gl-595:i386", "ros-humble-rclcpp", "python3.10"):
        assert inv.PACKAGE_NAME_RE.match(good), good
    for bad in ("", "-oops", "--force", "Foo", "a b", "x;y", "$(id)", "`id`", "a\nb", "../etc", "x|y"):
        assert not inv.PACKAGE_NAME_RE.match(bad), repr(bad)


def test_stack_patterns_do_not_sweep_in_unrelated_libraries() -> None:
    # Regression: a "libcu" prefix would also catch these, and holding them
    # would block their security fixes.
    nvidia = group_pattern("nvidia")
    for innocent in ("libcurl4", "libcurl3-gnutls", "libcups2", "libcue2", "curl", "libcupsfilters1", "libncurses6"):
        assert not nvidia.match(innocent), innocent
    for mine in (
        "nvidia-driver-595-open", "libnvidia-gl-595", "xserver-xorg-video-nvidia-595",
        "cuda-toolkit-12-6", "libcublas-12-6", "libcusolver-dev-12-6", "libnvidia-container1",
        "nvidia-container-toolkit",
    ):
        assert nvidia.match(mine), mine


def test_ros_and_gazebo_patterns() -> None:
    ros = group_pattern("ros2")
    for mine in ("ros-humble-rclcpp", "ros-humble-ros-base", "ros-noetic-roscpp", "ros-jazzy-foo"):
        assert ros.match(mine), mine
    # repo-config packages and unrelated names are not part of the stack
    for other in ("ros-apt-source", "ros2-apt-source", "rosdep", "python3-rosdep2", "libros1"):
        assert not ros.match(other), other
    gz = group_pattern("gazebo")
    for mine in ("libgz-sensors8", "libignition-common4", "gz-tools2", "sdformat-sdf", "libsdformat14"):
        assert gz.match(mine), mine
    # "gz" alone is not enough: only "gz-" / "libgz-" are Gazebo.
    for other in ("gzip", "libgzstream0", "libgzip-dev"):
        assert not gz.match(other), other


def test_normalize_pkg() -> None:
    assert inv.normalize_pkg("libfoo:amd64", "amd64") == "libfoo"
    assert inv.normalize_pkg("libfoo", "amd64") == "libfoo"
    assert inv.normalize_pkg("libfoo:i386", "amd64") == "libfoo:i386"  # foreign arch is a distinct package


def test_hold_group_states() -> None:
    installed = ["ros-humble-a", "ros-humble-b:amd64", "bash", "libnvidia-gl-595:i386"]
    none = {g["id"]: g for g in inv.hold_group_status(installed, set(), "amd64")}
    assert none["ros2"]["state"] == "none" and none["ros2"]["installed"] == 2
    assert none["gazebo"]["state"] == "absent"
    assert none["nvidia"]["installed"] == 1

    partial = {g["id"]: g for g in inv.hold_group_status(installed, {"ros-humble-a"}, "amd64")}
    assert partial["ros2"]["state"] == "partial" and partial["ros2"]["held"] == 1

    # held set is normalized: the :amd64 qualifier on an installed name still matches.
    full = {g["id"]: g for g in inv.hold_group_status(installed, {"ros-humble-a", "ros-humble-b"}, "amd64")}
    assert full["ros2"]["state"] == "all"
    foreign = {g["id"]: g for g in inv.hold_group_status(installed, {"libnvidia-gl-595:i386"}, "amd64")}
    assert foreign["nvidia"]["state"] == "all"


def test_names_for_hold_and_release(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(inv, "_native_arch", lambda: "amd64")
    monkeypatch.setattr(
        inv,
        "installed_packages",
        lambda: ["ros-humble-b", "ros-humble-a", "ros-humble-held:amd64", "bash", "ros-humble-A", "ros-humble-x;y"],
    )
    monkeypatch.setattr(inv, "held_packages", lambda arch: {"ros-humble-held"})
    # to hold: the not-yet-held ones, sorted; invalid names never get through
    assert inv.names_for_hold("ros2", release=False) == ["ros-humble-a", "ros-humble-b"]
    # to release: only what is currently held
    assert inv.names_for_hold("ros2", release=True) == ["ros-humble-held:amd64"]
    assert inv.names_for_hold("nope", release=False) is None


def test_parse_apt_upgradable() -> None:
    text = (
        "Listing...\n"
        "chatgpt/stable 26.1002.52244 amd64 [upgradable from: 26.908.40834]\n"
        "libfoo/jammy-updates,jammy-security 1.2-1ubuntu0.2 i386 [upgradable from: 1.2-1ubuntu0.1]\n"
        "not a package line\n"
    )
    found = inv.parse_apt_upgradable(text)
    assert found["chatgpt"] == {"installed": "26.908.40834", "candidate": "26.1002.52244"}
    assert found["libfoo"]["candidate"] == "1.2-1ubuntu0.2"
    assert len(found) == 2

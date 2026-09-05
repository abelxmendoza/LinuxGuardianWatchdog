"""Grouped process inventory: impact never auto-promotes unknown to close_app."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "LinuxGuardianSuite"))

from process_inventory import _assign_group  # noqa: E402


def test_systemd_split() -> None:
    assert _assign_group("systemd", 1, "/sbin/init", "/sbin/init")[0] == "systemd-pid1"
    assert _assign_group("systemd", 4371, "/lib/systemd/systemd --user", "/lib/systemd/systemd")[0] == "systemd-user"


def test_gnome_and_ros() -> None:
    assert _assign_group("gsd-power", 10, "/usr/libexec/gsd-power", "/usr/libexec/gsd-power")[0] == "gnome-settings"
    assert _assign_group("gvfsd-trash", 11, "", "/usr/libexec/gvfsd-trash")[0] == "gnome-files"
    gid, _t, _b, impact = _assign_group(
        "python3", 12, "python3 /opt/ros/jazzy/bin/ros2 run topic_tools mux", "/usr/bin/python3"
    )
    assert gid == "ros2"
    assert impact == "feature_stops"


def test_unknown_is_never_close_app() -> None:
    gid, _t, _b, impact = _assign_group("weirdbin", 99, "/tmp/weirdbin", "/tmp/weirdbin")
    assert gid == "unknown"
    assert impact == "unknown"


def test_firefox_helpers() -> None:
    assert _assign_group("Web Content", 20, "/usr/lib/firefox/firefox", "")[0] == "firefox"


def test_system_subsystems() -> None:
    cases = {
        "systemd-journald": "logging",
        "rsyslogd": "logging",
        "systemd-udevd": "hardware",
        "systemd-oomd": "memory",
        "systemd-timesyncd": "time",
        "cron": "scheduled",
        "upowerd": "power",
        "power-profiles-daemon": "power",
        "snapd": "packages",
        "unattended-upgrades": "packages",
        "systemd-logind": "login",
        "gdm3": "login",
        "udisksd": "storage",
        "polkitd": "permissions",
        "cupsd": "printing",
    }
    for comm, gid in cases.items():
        got = _assign_group(comm, 50, f"/{comm}", f"/usr/lib/{comm}")[0]
        assert got == gid, f"{comm} -> {got}, expected {gid}"


def test_unit_and_truncated_names() -> None:
    assert (
        _assign_group("systemd-journal", 8, "", "/lib/systemd/systemd-journald", "systemd-journald.service")[0]
        == "logging"
    )
    assert _assign_group("run-cups-browse", 9, "/usr/sbin/cups-browsed", "/usr/sbin/cups-browsed")[0] == "printing"


def test_user_owned_unknown_stays_unknown() -> None:
    gid, _t, _b, impact = _assign_group("sleep", 70, "sleep 30", "/usr/bin/sleep")
    assert gid == "unknown"
    assert impact == "unknown"


if __name__ == "__main__":
    test_systemd_split()
    test_gnome_and_ros()
    test_unknown_is_never_close_app()
    test_firefox_helpers()
    test_system_subsystems()
    test_unit_and_truncated_names()
    test_user_owned_unknown_stays_unknown()
    print("OK")

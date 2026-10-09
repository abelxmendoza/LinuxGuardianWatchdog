"""Package names become plain-language groups, and apt's output becomes progress a person can follow."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from linuxguardian_ui import update_catalog as c  # noqa: E402


@pytest.mark.parametrize("name,group", [
    ("linux-modules-5.15.0-164-generic", "kernel"), ("linux-image-generic-hwe-22.04", "kernel"), ("intel-microcode", "kernel"),
    ("nvidia-driver-590-open", "graphics"), ("libnvidia-gl-590:i386", "graphics"), ("mesa-vulkan-drivers", "graphics"),
    ("firefox", "browsers"), ("chromium-browser", "browsers"),
    ("ros-humble-rclcpp", "robotics"), ("gz-harmonic", "robotics"), ("ignition-fortress", "robotics"),
    ("libssl3", "security"), ("openssl", "security"), ("libkrb5-3", "security"), ("ca-certificates", "security"), ("sudo", "security"),
    ("curl", "network"), ("libcurl4", "network"), ("netplan.io", "network"), ("dnsmasq-base", "network"),
    ("python3-lxml", "python"), ("libpython3.10", "python"),
    ("gdm3", "desktop"), ("libgtk-3-0", "desktop"), ("fonts-ubuntu", "desktop"),
    ("cups-daemon", "printing"), ("libpng16-16", "media"), ("ffmpeg", "media"),
    ("libreoffice-core", "office"), ("gcc-11", "dev"), ("libssl-dev", "security"), ("libfoo-dev", "dev"),
    ("systemd", "system"), ("libc6", "system"), ("tzdata", "system"),
    ("claude-desktop", "apps"), ("tailscale", "network"),
    ("libsomethingobscure2", "libs"), ("msr-tools", "other"),
])
def test_classification(name, group):
    assert c.classify(name).id == group, (name, c.classify(name).id)


def test_third_party_and_snap_apps_are_apps_unless_clearly_something_else():
    assert c.classify("cursor", "third_party").id == "apps"
    assert c.classify("postman", "snap").id == "apps"
    assert c.classify("ros-humble-desktop", "third_party").id == "robotics"        # a ROS package from the ROS repo
    assert c.classify("cuda-toolkit-12-6", "third_party").id == "graphics"


def test_architecture_suffix_is_ignored():
    assert c.classify("libnvidia-gl-590:i386") == c.classify("libnvidia-gl-590")
    assert c.friendly_name("libssl3:amd64") == "OpenSSL library"


@pytest.mark.parametrize("name,friendly", [
    ("firefox", "Firefox"), ("code", "Visual Studio Code"), ("libssl3", "OpenSSL library"), ("libc6", "C library (glibc)"),
    ("linux-modules-5.15.0-164-generic", "Kernel modules 5.15.0-164"), ("linux-image-generic-hwe-22.04", "Linux kernel (latest)"),
    ("nvidia-driver-590-open", "NVIDIA driver 590"), ("ros-humble-rclcpp", "ROS 2 Humble: rclcpp"), ("python3-lxml", "Python: lxml"),
    ("libgtk-3-0", "gtk library"), ("libfoo-dev", "foo developer files"), ("libpng16-16", "png16 library"), ("libpng-tools", "png tools"), ("libaudit-common", "audit common"), ("msr-tools", "msr tools"),
])
def test_friendly_names(name, friendly):
    assert c.friendly_name(name) == friendly


@pytest.mark.parametrize("name", ["", "x", "lib", "libx", "weird_name!", "a" * 200, "lib-", "ros-", "python3-"])
def test_friendly_name_never_fails_or_comes_back_empty(name):
    assert c.friendly_name(name) is not None and (name == "" or c.friendly_name(name) != "")
    assert c.classify(name) is not None


def test_grouping_is_ordered_and_keeps_every_package():
    items = [{"name": n} for n in ["libssl3", "firefox", "linux-image-5.15.0-164-generic", "curl", "ros-humble-rclcpp", "msr-tools"]]
    grouped = c.group_items(items)
    assert [g.id for g, _ in grouped] == ["kernel", "security", "browsers", "network", "robotics", "other"]
    assert sorted(i["name"] for _g, rows in grouped for i in rows) == sorted(i["name"] for i in items)


def test_headline_prefers_recognisable_names_and_counts_the_rest():
    items = [{"name": n} for n in ["libssl3", "openssl", "libgcrypt20", "gnupg", "libgnutls30"]]
    h = c.headline(items, limit=2)
    assert h.startswith("GnuPG (encryption), OpenSSL") and h.endswith("+2 more")      # "OpenSSL library" folds into "OpenSSL"
    assert "OpenSSL library" not in h


def test_plural():
    assert c.plural(1, "package") == "1 package" and c.plural(2, "package") == "2 packages"


# ------------------------------------------------------------------ install output
LOG = """\
Reading package lists...
48 upgraded, 1 newly installed, 0 to remove and 20 not upgraded.
Get:1 https://downloads.cursor.com/aptrepo stable/main amd64 cursor amd64 3.23.23 [208 MB]
Preparing to unpack .../libaudit1_1%3a3.0.7-1ubuntu0.1_amd64.deb ...
Unpacking libaudit1:amd64 (1:3.0.7-1ubuntu0.1) over (1:3.0.7-1build1) ...
Setting up libaudit1:amd64 (1:3.0.7-1ubuntu0.1) ...
Unpacking cursor (3.23.23) over (3.20.0) ...
Setting up cursor (3.23.23) ...
Processing triggers for libc-bin (2.35-0ubuntu3.11) ...
Unpacking brandnew (1.0) ...
Setting up brandnew (1.0) ...
chromium 155.0.8059.39 from Canonical** refreshed
"""


def run(lines: str) -> c.InstallLog:
    log = c.InstallLog()
    for line in lines.splitlines():
        log.feed(line)
    return log


def test_log_reads_what_finished_with_old_and_new_versions():
    log = run(LOG)
    assert set(log.done) == {"libaudit1", "cursor", "brandnew", "chromium"}
    assert log.done["libaudit1"].old == "1:3.0.7-1build1" and log.done["libaudit1"].new == "1:3.0.7-1ubuntu0.1"
    assert log.done["brandnew"].old == "" and log.done["chromium"].manager == "snap"


def test_log_knows_how_many_to_expect_and_reports_progress():
    log = c.InstallLog()
    log.feed("48 upgraded, 1 newly installed, 0 to remove and 20 not upgraded.")
    assert log.expected == 49 and log.fraction() == 0.0
    for i in range(10):
        log.feed(f"Setting up pkg{i} (1.0) ...")
    assert 0.2 < log.fraction() < 0.21


def test_progress_never_reaches_100_before_the_job_is_done():
    log = c.InstallLog()
    log.feed("1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.")
    log.feed("Setting up a (1) ...")
    assert log.fraction() < 1.0


def test_log_current_is_a_human_name_not_a_package():
    log = c.InstallLog()
    log.feed("Unpacking libssl3:amd64 (3.0.2-0ubuntu1.20) over (3.0.2-0ubuntu1.18) ...")
    assert log.current == "OpenSSL library"


def test_noise_lines_are_ignored():
    log = c.InstallLog()
    for line in ["Get:1 http://x InRelease", "Processing triggers for man-db", "(Reading database ... 12%", "", "Setting up", "Unpacking"]:
        assert log.feed(line) is None
    assert not log.done


def test_items_shape_feeds_the_grouper():
    items = run(LOG).items()
    grouped = c.group_items(items)
    assert {"apps", "security", "browsers"} <= {g.id for g, _ in grouped}


def test_unattended_upgrade_announces_a_plan_and_prints_no_per_package_lines():
    log = c.InstallLog()
    log.feed("Packages that will be upgraded: libssl3 openssl firefox")
    assert log.expected == 3 and not log.done
    log.complete_from_plan({"libssl3": ("3.0.2-18", "3.0.2-20"), "openssl": ("3.0.2-18", "3.0.2-20")})
    assert set(log.done) == {"libssl3", "openssl", "firefox"}
    assert log.done["libssl3"].old == "3.0.2-18" and log.done["firefox"].new == ""


def test_complete_from_plan_never_overwrites_what_was_actually_seen():
    log = c.InstallLog()
    log.feed("Packages that will be upgraded: curl")
    log.feed("Setting up curl (7.99) ...")
    log.complete_from_plan({"curl": ("7.0", "7.1")})
    assert log.done["curl"].new == "7.99"

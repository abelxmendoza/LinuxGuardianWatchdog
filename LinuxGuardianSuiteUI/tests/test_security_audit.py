"""Audit regressions: unavailable evidence must not become a security pass."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SUITE = Path(__file__).resolve().parents[2] / "LinuxGuardianSuite"
sys.path.insert(0, str(SUITE))

import update_inventory as ui  # noqa: E402


@pytest.mark.parametrize(
    "raw_tools,expected",
    [
        ("nft", "unknown"),       # raw rules exist but are root-only to read: can't call it protected OR unprotected
        ("iptables", "unknown"),
        ("", "none"),             # every readable front-end is verifiably off
    ],
)
def test_unreadable_raw_rules_are_unknown_not_none(raw_tools, expected):
    script = r'''
source "$1/utils.sh"
command() { [[ "$1" == "-v" ]] && [[ " $RAW " == *" $2 "* ]]; }
systemctl() { return 3; }          # no front-end service is running
id() { echo 1000; }                # an ordinary user
LG_UFW_CONF=/nonexistent lg_detect_firewall
'''
    result = subprocess.run(["bash", "-c", script, "audit-test", str(SUITE)],
                            env={**os.environ, "RAW": raw_tools}, capture_output=True, text=True, check=True)
    assert result.stdout.strip() == expected


GOOD = 'APT::Periodic::Unattended-Upgrade "1";\nAPT::Periodic::Update-Package-Lists "1";'


@pytest.mark.parametrize(
    "periodic,enabled,active,expected",
    [
        (GOOD, "enabled", "active", "on"),
        ('APT::Periodic::Unattended-Upgrade "0";', "enabled", "active", "off"),
        (GOOD + '\nAPT::Periodic::Enable "0";', "enabled", "active", "off"),       # everything periodic disabled
        ('APT::Periodic::Unattended-Upgrade "1";', "enabled", "active", "off"),    # lists never refreshed: nothing to upgrade
        (GOOD, "disabled", "inactive", "off"),
        (GOOD, "enabled", "inactive", "off"),                                       # enabled but not actually running
    ],
)
def test_auto_security_updates_need_settings_and_a_running_timer(monkeypatch, periodic, enabled, active, expected):
    answers = {
        ("apt-config", "dump"): periodic,
        ("systemctl", "is-enabled", "apt-daily-upgrade.timer"): enabled,
        ("systemctl", "is-active", "apt-daily-upgrade.timer"): active,
    }
    monkeypatch.setattr(ui, "_run", lambda cmd, timeout: answers.get(tuple(cmd)))
    monkeypatch.setattr(ui.shutil, "which", lambda name: "/usr/bin/" + name)
    assert ui.auto_security_status()["auto_security_updates"] == expected


def test_tool_missing_means_off(monkeypatch):
    monkeypatch.setattr(ui, "_run", lambda cmd, timeout: GOOD if cmd[0] == "apt-config" else "enabled" if "is-enabled" in cmd else "active")
    monkeypatch.setattr(ui.shutil, "which", lambda name: None)
    assert ui.auto_security_status()["auto_security_updates"] == "off"

"""Notifications: only things that may have HAPPENED (incidents) and critical standing findings, once, grouped, never replaying history."""
from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import notify_events as ne  # noqa: E402

NOW = 1_800_000_000.0


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "home"))
    log = tmp_path / "calls.log"
    stub = tmp_path / "notify-send"
    stub.write_text(f'#!/bin/sh\nprintf \'%s\\n\' "$*" >> "{log}"\n')
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("LG_NOTIFY_CMD", str(stub))
    (tmp_path / "home" / "incidents").mkdir(parents=True)
    return tmp_path


def event(env: Path, name: str, epoch: float, severity="warning", message="m", category="sensor", **extra) -> None:
    rec = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(epoch)), "category": category,
           "severity": severity, "message": message, **extra}
    (env / "home" / "incidents" / f"{name}.json").write_text(json.dumps(rec))


def calls(env: Path) -> list[str]:
    p = env / "calls.log"
    return p.read_text().splitlines() if p.exists() else []


def test_first_run_only_sets_a_starting_point(env):
    event(env, "old", NOW - 5000, message="ancient history")
    assert ne.run_send(NOW) == 0 and calls(env) == []


def test_new_warning_is_announced_exactly_once(env):
    ne.run_send(NOW)
    event(env, "a", NOW + 10, message="A program connected to the internet for the first time")
    assert ne.run_send(NOW + 20) == 1
    [call] = calls(env)
    assert "A program connected to the internet for the first time" in call and "-u normal" in call
    assert ne.run_send(NOW + 30) == 0 and len(calls(env)) == 1


def test_critical_uses_critical_urgency(env):
    ne.run_send(NOW)
    event(env, "a", NOW + 10, severity="critical", message="Honeypot accessed", category="honeypot")
    ne.run_send(NOW + 20)
    assert "-u critical" in calls(env)[0]


def test_routine_and_resolved_events_stay_quiet(env):
    ne.run_send(NOW)
    event(env, "a", NOW + 10, severity="info", message="Killed PID 5")
    event(env, "b", NOW + 11, severity="info", status="resolved", message="Resolved: x")
    assert ne.run_send(NOW + 20) == 0 and calls(env) == []


def test_several_new_findings_become_one_notification(env):
    ne.run_send(NOW)
    for i, word in enumerate(["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"]):
        event(env, f"e{i}", NOW + 10 + i, message=f"finding {word}")
    assert ne.run_send(NOW + 30) == 6
    text = "\n".join(calls(env))
    assert text.count("LinuxGuardian:") == 1                     # one notification, not six
    assert "6 new findings" in text and "and 2 more" in text and "finding foxtrot" in text and "finding alpha" not in text


def test_disabled_sends_nothing_and_does_not_queue_up(env):
    ne.run_send(NOW)
    ne.set_enabled(False)
    event(env, "a", NOW + 10, message="while off")
    assert ne.run_send(NOW + 20) == 0
    ne.set_enabled(True)
    assert ne.run_send(NOW + 30) == 0      # not announced late either; the Timeline still has it


def test_missing_notify_send_is_harmless(env, monkeypatch):
    monkeypatch.setenv("LG_NOTIFY_CMD", "definitely-not-installed")
    ne.run_send(NOW)
    event(env, "a", NOW + 10)
    assert ne.run_send(NOW + 20) == 0


# ----------------------------------------------------- incidents versus findings versus information
def test_a_standing_configuration_warning_never_interrupts(env):
    ne.run_send(NOW)
    event(env, "a", NOW + 10, category="audit", message="No LUKS-encrypted volume detected")
    event(env, "b", NOW + 11, category="audit", message="7 security update(s) pending")
    event(env, "c", NOW + 12, category="rootkit", message="rkhunter reported warnings")
    event(env, "d", NOW + 13, category="network", message="VNC is reachable")
    assert ne.run_send(NOW + 20) == 0 and calls(env) == []


def test_a_critical_standing_finding_is_announced_once(env):
    ne.run_send(NOW)
    event(env, "a", NOW + 10, category="audit", severity="critical", message="No active firewall detected")
    assert ne.run_send(NOW + 20) == 1 and len(calls(env)) == 1
    assert ne.run_send(NOW + 30) == 0


def test_edits_to_your_own_documents_are_information_not_alarms(env):
    ne.run_send(NOW)
    event(env, "a", NOW + 10, category="integrity", event="file_modified", message="File changed: /home/me/Documents/resume.pdf")
    event(env, "b", NOW + 11, category="integrity", event="file_missing", message="File missing: /home/me/Documents/old.txt")
    assert ne.run_send(NOW + 20) == 0


def test_a_change_where_programs_start_from_does_interrupt(env):
    ne.run_send(NOW)
    event(env, "a", NOW + 10, category="integrity", event="file_new_persistence", message="New file in a start-up/persistence location: ~/.config/autostart/x.desktop")
    assert ne.run_send(NOW + 20) == 1


def test_incidents_and_findings_are_mixed_correctly_in_one_batch(env):
    ne.run_send(NOW)
    event(env, "a", NOW + 10, category="audit", message="No LUKS-encrypted volume detected")
    event(env, "b", NOW + 11, category="sensor", event="tripwire_ssh_key_added", severity="critical", message="A new SSH key was added")
    assert ne.run_send(NOW + 20) == 1 and "A new SSH key was added" in calls(env)[0] and "LUKS" not in calls(env)[0]


def test_kind_of_classifies_every_category_the_suite_writes():
    from events import kind_of
    assert kind_of("sensor", "warning") == "incident" and kind_of("malware", "critical") == "incident" and kind_of("honeypot", "critical") == "incident"
    assert kind_of("selfcheck", "warning", "monitoring_stopped") == "incident"
    assert kind_of("audit", "warning") == "finding" and kind_of("network", "warning") == "finding" and kind_of("rootkit", "warning") == "finding"
    assert kind_of("integrity", "warning", "file_modified") == "finding" and kind_of("integrity", "warning", "file_new_persistence") == "incident"
    assert kind_of("integrity", "warning", "file_changes") == "incident"                   # a burst of changes is not routine
    assert kind_of("sensor", "info") == "information" and kind_of("audit", "info") == "information" and kind_of("process", "info") == "information"
    assert kind_of("something_new", "warning") == "finding"                                  # unknown categories are never silently incidents

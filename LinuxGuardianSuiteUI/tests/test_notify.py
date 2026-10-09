"""Notifications: only NEW warning/critical findings, once, grouped, and never replaying history."""
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


def event(env: Path, name: str, epoch: float, severity="warning", message="m", **extra) -> None:
    rec = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(epoch)), "category": "audit",
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
    event(env, "a", NOW + 10, message="No LUKS-encrypted volume detected")
    assert ne.run_send(NOW + 20) == 1
    [call] = calls(env)
    assert "No LUKS-encrypted volume detected" in call and "-u normal" in call
    assert ne.run_send(NOW + 30) == 0 and len(calls(env)) == 1


def test_critical_uses_critical_urgency(env):
    ne.run_send(NOW)
    event(env, "a", NOW + 10, severity="critical", message="Honeypot accessed")
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

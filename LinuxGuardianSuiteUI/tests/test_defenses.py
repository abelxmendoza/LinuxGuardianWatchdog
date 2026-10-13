"""Defenses watch: only a protection that WAS on and then went off is news; reboots, never-on services and unknowns are not."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import defenses as df  # noqa: E402
import incidents  # noqa: E402
import self_check as sc  # noqa: E402
import sensors as sn  # noqa: E402
from test_sensors import at, box, sensor_events  # noqa: E402,F401  (box is a fixture)


@pytest.fixture()
def world(box, monkeypatch):
    """A fake system: ufw.conf, /etc/default/ufw and a systemctl whose answers come from files in box/svc."""
    (box / "svc").mkdir()
    (box / "bin/systemctl").write_text(
        '#!/bin/sh\n'
        'case "$1" in\n'
        '  show) unit="$4"; f="' + str(box / "svc") + '/$unit"; if [ -f "$f" ]; then echo "LoadState=loaded"; echo "ActiveState=$(cat $f)"; else echo "LoadState=not-found"; fi ;;\n'
        '  --user) f="' + str(box / "svc") + '/timer"; [ -f "$f" ] && cat "$f" || echo disabled ;;\n'
        'esac\n')
    (box / "bin/systemctl").chmod(0o755)
    set_ufw(box, enabled=True, policy="DROP")
    for u in ("ufw", "clamav-freshclam", "apparmor"):
        svc(box, u, "active")
    return box


def set_ufw(box: Path, enabled: bool, policy: str) -> None:
    (box / "ufw.conf").write_text(f"ENABLED={'yes' if enabled else 'no'}\nLOGLEVEL=low\n")
    (box / "ufw.default").write_text(f'DEFAULT_INPUT_POLICY="{policy}"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n')


def svc(box: Path, unit: str, state: str | None) -> None:
    p = box / "svc" / unit
    if state is None:
        p.unlink(missing_ok=True)
    else:
        p.write_text(state)


def look(state: dict) -> list[dict]:
    return df.run(state)


def learn() -> dict:
    state: dict = {}
    assert look(state) == []
    return state


# ------------------------------------------------------------------ observing
def test_observe_reads_config_policy_and_service_states(world):
    o = df.observe()
    assert o == {"ufw_enabled": True, "ufw_active": True, "ufw_policy": "DROP", "freshclam": True, "apparmor": True}
    svc(world, "apparmor", "inactive")
    set_ufw(world, False, "ACCEPT")
    svc(world, "clamav-freshclam", None)                                  # not installed
    o = df.observe()
    assert o["apparmor"] is False and o["ufw_enabled"] is False and o["ufw_policy"] == "ACCEPT" and o["freshclam"] is None


def test_missing_files_and_no_systemctl_are_unknown_not_alarming(world, monkeypatch):
    (world / "ufw.conf").unlink()
    (world / "ufw.default").unlink()
    monkeypatch.setenv("PATH", "/nonexistent")
    o = df.observe()
    assert o == {"ufw_enabled": None, "ufw_active": None, "ufw_policy": None, "freshclam": None, "apparmor": None}


# ------------------------------------------------------------------- firewall
def test_the_first_look_only_learns_even_if_things_are_off(world):
    set_ufw(world, False, "ACCEPT")
    svc(world, "ufw", "inactive")
    assert learn() is not None                                           # no alerts: that is the Hardening tab's business


def test_switching_the_firewall_off_is_critical_at_once(world):
    state = learn()
    set_ufw(world, False, "DROP")
    [f] = look(state)
    assert f["event"] == "defense_disabled" and f["severity"] == "critical" and f["technique"] == "T1562.004" and "switched off" in f["message"]
    assert look(state) == []                                              # reported once


def test_opening_the_default_policy_is_critical(world):
    state = learn()
    set_ufw(world, True, "ACCEPT")
    [f] = look(state)
    assert f["severity"] == "critical" and "ACCEPT" in f["message"] and f["entity"] == ["/etc/default/ufw"]


def test_changing_between_safe_policies_is_not_news(world):
    state = learn()
    set_ufw(world, True, "REJECT")
    assert look(state) == []


def test_a_policy_that_was_already_open_stays_quiet_on_later_looks(world):
    set_ufw(world, True, "ACCEPT")
    state = learn()
    for _ in range(3):
        assert look(state) == []


def test_a_firewall_that_was_never_on_is_never_reported_as_switched_off(world):
    set_ufw(world, False, "DROP")
    svc(world, "ufw", "inactive")
    state = learn()
    for _ in range(4):
        assert look(state) == []


# ------------------------------------------------------------------- services
def test_a_service_must_stay_down_for_two_looks_before_it_is_reported(world):
    state = learn()
    svc(world, "ufw", "inactive")
    assert look(state) == []                                              # one look: could be a reboot or a restart
    [f] = look(state)
    assert f["severity"] == "critical" and "firewall service" in f["message"] and f["technique"] == "T1562.004"
    assert look(state) == [] and look(state) == []                        # once per outage


def test_a_service_that_comes_back_before_the_second_look_is_forgiven(world):
    state = learn()
    svc(world, "ufw", "inactive")
    assert look(state) == []
    svc(world, "ufw", "active")
    assert look(state) == []
    svc(world, "ufw", "inactive")
    assert look(state) == []                                              # the count started over
    assert len(look(state)) == 1


def test_a_second_outage_is_reported_again(world):
    state = learn()
    svc(world, "apparmor", "inactive")
    look(state)
    assert len(look(state)) == 1
    svc(world, "apparmor", "active")
    look(state)
    svc(world, "apparmor", "inactive")
    look(state)
    assert len(look(state)) == 1


def test_virus_updater_and_apparmor_are_warnings(world):
    state = learn()
    svc(world, "clamav-freshclam", "inactive")
    svc(world, "apparmor", "failed")
    look(state)
    found = look(state)
    assert sorted((f["severity"], f["technique"]) for f in found) == [("warning", "T1562.001"), ("warning", "T1562.001")]
    assert any("virus-definition updater" in f["message"] for f in found) and any("AppArmor" in f["message"] for f in found)


def test_a_service_that_was_never_running_is_not_reported(world):
    svc(world, "apparmor", "inactive")
    state = learn()
    for _ in range(4):
        assert look(state) == []


def test_a_service_that_is_removed_is_not_reported_as_stopped(world):
    state = learn()
    svc(world, "clamav-freshclam", None)                                  # uninstalled: the package manager's doing, not an attack
    for _ in range(4):
        assert look(state) == []


# --------------------------------------------------------- sensor + incidents
def test_the_sensor_reports_a_stopped_firewall_with_its_own_story(world, monkeypatch):
    sn.run_once()
    set_ufw(world, False, "DROP")
    at(monkeypatch, 600)
    sn.run_once()
    [e] = sensor_events(world)
    assert e["event"] == "defense_disabled" and e["severity"] == "critical" and e["stage"] == "defense-evasion"
    [inc] = incidents.build(days=7, directory=world / "lg" / "incidents", now=time.time() + 60)
    assert inc.title == "A protection was switched off" and inc.severity == "critical"
    assert "sudo ufw enable" in " ".join(inc.next_steps)


def test_cli(world, capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["defenses.py", "--check"])
    assert df.main() == 0
    out = capsys.readouterr().out
    assert "Firewall: enabled in config on, service on, incoming default DROP" in out and "AppArmor: on" in out
    monkeypatch.setattr(sys, "argv", ["defenses.py", "--check", "--json"])
    assert df.main() == 0 and json.loads(capsys.readouterr().out)["now"]["ufw_policy"] == "DROP"


# ------------------------------------------------------ the dead-man's switch
def beat_state(box: Path, last_run_ago: float | None, timer_seen: bool = True, timer: str = "enabled"):
    (box / "lg/state").mkdir(parents=True, exist_ok=True)
    now = time.time()
    st = {"timer_seen": timer_seen}
    if last_run_ago is not None:
        st["last_run"] = now - last_run_ago
    (box / "lg/state/sensors.json").write_text(json.dumps(st))
    (box / "svc/timer").write_text(timer)


def hb_events(box: Path) -> list[dict]:
    import events
    return [e for e in events.read_events(box / "lg" / "incidents", limit=50) if e.get("event") == "monitoring_stopped"]


def test_heartbeat_speaks_when_the_timer_was_switched_off(world, monkeypatch):
    monkeypatch.setenv("LG_SELF_NOW", str(time.time()))
    beat_state(world, 120, timer="disabled")
    r = sc.heartbeat()
    assert r and "switched off" in r["message"]
    [e] = hb_events(world)
    assert e["severity"] == "warning" and e["category"] == "selfcheck" and "systemctl --user enable --now" in e["message"]


def test_heartbeat_speaks_when_the_monitor_stopped_running(world, monkeypatch):
    monkeypatch.setenv("LG_SELF_NOW", str(time.time()))
    beat_state(world, 7.5 * 3600)
    r = sc.heartbeat()
    assert r and "hasn't run for 7 hours" in r["message"]


def test_heartbeat_is_quiet_when_monitoring_is_healthy(world, monkeypatch):
    monkeypatch.setenv("LG_SELF_NOW", str(time.time()))
    beat_state(world, 600)
    assert sc.heartbeat() is None and hb_events(world) == []


def test_heartbeat_never_nags_someone_who_never_used_live_monitoring(world, monkeypatch):
    monkeypatch.setenv("LG_SELF_NOW", str(time.time()))
    beat_state(world, 30 * 86400, timer_seen=False, timer="disabled")
    assert sc.heartbeat() is None
    (world / "lg/state/sensors.json").unlink()
    assert sc.heartbeat() is None


def test_heartbeat_speaks_at_most_once_a_day(world, monkeypatch):
    t = time.time()
    monkeypatch.setenv("LG_SELF_NOW", str(t))
    beat_state(world, 120, timer="disabled")
    assert sc.heartbeat() is not None
    monkeypatch.setenv("LG_SELF_NOW", str(t + 3600))
    assert sc.heartbeat() is None
    monkeypatch.setenv("LG_SELF_NOW", str(t + 25 * 3600))
    beat_state(world, 120, timer="disabled")
    assert sc.heartbeat() is not None and len(hb_events(world)) == 2


def test_the_sensor_notes_that_live_monitoring_is_really_in_use(world):
    (world / "svc/timer").write_text("enabled")
    sn.run_once()
    assert json.loads((world / "lg/state/sensors.json").read_text()).get("timer_seen") is True


def test_the_daily_scan_runs_the_heartbeat_from_its_own_unit():
    src = (ROOT / "LinuxGuardianSuite" / "linux_guardian.sh").read_text()
    assert 'self_check.py" --heartbeat' in src and src.index("--heartbeat") < src.index("Malware/rootkit scan of")


def test_heartbeat_cli(world, capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["self_check.py", "--heartbeat"])
    assert sc.main() == 0 and "fine" in capsys.readouterr().out

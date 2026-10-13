"""Integration: the components agree with each other, end to end through the real code (no mocks between them).

   sensor -> event file -> classification -> notification decision -> Timeline -> incident story
   audit script -> events -> rating shown by the app
   configuration change -> runtime behaviour
   failure in one part -> the rest keeps working and the failure is visible
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "LinuxGuardianSuite"
sys.path.insert(0, str(SUITE))
sys.path.insert(0, str(ROOT / "LinuxGuardianSuiteUI"))

import audit_events  # noqa: E402
import events  # noqa: E402
import incidents  # noqa: E402
import notify_events  # noqa: E402
import sensors as sn  # noqa: E402
import timeline  # noqa: E402
from linuxguardian_ui.score import parse_audit_score  # noqa: E402
from test_sensors import DAY, T0, add_proc, add_usb, at, box, sensor_events, ss_line, stub  # noqa: E402,F401  (box is a fixture)


@pytest.fixture()
def popups(box, monkeypatch):
    """Desktop notifications recorded instead of shown."""
    log = box / "popups.log"
    stub(box / "bin", "notify-send", f'printf "%s\\n" "$*" >> "{log}"')
    monkeypatch.setenv("LG_NOTIFY_CMD", str(box / "bin" / "notify-send"))
    notify_events.run_send(1.0)                                        # first run only sets the starting point

    class P:
        def sent(self) -> list[str]:
            return log.read_text().splitlines() if log.exists() else []

        def now(self) -> int:
            return notify_events.run_send(time.time() + 5)

    return P()


def learn(box, monkeypatch) -> None:
    sn.run_once()
    at(monkeypatch, 4 * DAY)


# =============================================================== 1-4: sensor -> event -> class -> notification -> timeline
SCENARIOS = {
    # name: (how to provoke it, expected event, expected kind, notifies?)
    "dropper": ("dropper", "proc_from_tmp", "incident", True),
    "badusb": ("badusb", "new_usb_composite", "incident", True),
    "newcmd": ("newcmd", "new_local_command", "information", False),
    "usb_plain": ("usb_plain", "new_usb", "information", False),
}


def provoke(box: Path, what: str) -> None:
    if what == "dropper":
        add_proc(box, 7, "/tmp/payload", ["/tmp/payload"])
    elif what == "badusb":
        add_usb(box, "1-1", "dead", "beef", ["03", "08"])
    elif what == "usb_plain":
        add_usb(box, "1-2", "046d", "c52b", ["03"])
    elif what == "newcmd":
        p = box / "home/.local/bin/mytool"
        p.write_text("#!/bin/sh\n")
        p.chmod(0o755)


@pytest.mark.parametrize("name", SCENARIOS)
def test_each_kind_of_sensor_event_is_classified_and_announced_by_policy(box, popups, monkeypatch, name):
    what, event, kind, notifies = SCENARIOS[name]
    learn(box, monkeypatch)
    provoke(box, what)
    sn.run_once()
    ev = [e for e in sensor_events(box) if e["event"] == event]
    assert len(ev) == 1, [e["event"] for e in sensor_events(box)]
    entry = next(e for e in timeline.load_entries(box / "lg" / "incidents") if event in str(e.extra.get("event")))
    assert entry.kind == kind and entry.category == "sensor" and entry.severity == ev[0]["severity"]      # classification agrees with the event
    popped = popups.now()
    assert (popped >= 1) is notifies and (len(popups.sent()) == 1) is notifies


def test_informational_events_never_produce_a_critical_notification(box, popups, monkeypatch):
    learn(box, monkeypatch)
    provoke(box, "newcmd")
    provoke(box, "usb_plain")
    sn.run_once()
    assert popups.now() == 0 and popups.sent() == []
    assert all(e["severity"] == "info" for e in sensor_events(box))


def test_a_legitimate_incident_stays_visible_everywhere(box, popups, monkeypatch):
    learn(box, monkeypatch)
    provoke(box, "dropper")
    sn.run_once()
    d = box / "lg" / "incidents"
    assert [e for e in events.read_events(d) if e["event"] == "proc_from_tmp"]                      # on disk
    assert any(e.kind == "incident" for e in timeline.load_entries(d))                              # in the Timeline
    [inc] = incidents.build(days=1, directory=d, now=time.time() + 60)                              # as a story
    assert "temporary folder" in inc.title and inc.severity in ("warning", "critical")
    assert popups.now() == 1                                                                       # and announced once
    assert popups.now() == 0                                                                       # not again


def test_acknowledging_hides_an_entry_until_the_same_thing_happens_again(box, monkeypatch):
    learn(box, monkeypatch)
    provoke(box, "dropper")
    sn.run_once()
    d = box / "lg" / "incidents"
    [entry] = [e for e in timeline.load_entries(d) if e.extra.get("event") == "proc_from_tmp"]
    timeline.acknowledge(entry.key, now=time.time() + 1)
    assert not [e for e in timeline.select(timeline.load_entries(d)) if e.key == entry.key]
    assert [e for e in timeline.select(timeline.load_entries(d), include_acknowledged=True) if e.key == entry.key]


# ================================================= 5: risk acceptance never suppresses an unrelated incident
LUKS = "No LUKS-encrypted volume detected — consider full-disk encryption"


def test_an_accepted_risk_and_a_real_incident_coexist(box, popups, monkeypatch):
    audit_events.accept(LUKS)
    audit_events.process([("warning", LUKS), ("warning", "7 security update(s) pending — install them from the Updates tab")])
    learn(box, monkeypatch)
    provoke(box, "dropper")
    sn.run_once()
    d = box / "lg" / "incidents"
    entries = timeline.load_entries(d)
    messages = [e.message for e in entries if e.status != "resolved"]
    assert any("LUKS" in m for m in messages)                                                     # the accepted finding is still recorded as accepted/visible
    assert any("7 security update" in m for m in messages)                                        # an unrelated finding is still there
    assert any(e.kind == "incident" and e.severity != "info" for e in entries)                    # and so is the incident
    assert popups.now() == 1 and "LUKS" not in popups.sent()[0]                                   # popup for the incident only


# ========================================================= 6: audit -> rating the app shows
def test_the_rating_the_app_displays_is_the_one_the_audit_computed(tmp_path, monkeypatch):
    b = tmp_path / "bin"
    b.mkdir()
    stub(b, "systemctl", 'case "$*" in *"is-active --quiet ufw"*) exit 0 ;; esac\nexit 3')
    stub(b, "sudo", "exit 1")
    (tmp_path / "ufw.conf").write_text("ENABLED=yes\n")
    env = {**os.environ, "PATH": f"{b}:/usr/bin:/bin", "LG_UFW_CONF": str(tmp_path / "ufw.conf"), "HOME": str(tmp_path), "LG_HOME": str(tmp_path / "lg"), "NO_COLOR": "1"}
    out = subprocess.run([str(SUITE / "linux_security_audit.sh")], capture_output=True, text=True, env=env).stdout
    score = parse_audit_score(out.splitlines())
    assert score and score.total == score.passed + score.warned + score.failed
    assert score.percent == (200 * score.passed + 100 * score.warned + score.total) // (2 * score.total)      # half credit for a warning
    subprocess.run([str(SUITE / "audit_events.py"), "--accept", LUKS], check=True, env=env, capture_output=True)
    out2 = subprocess.run([str(SUITE / "linux_security_audit.sh")], capture_output=True, text=True, env=env).stdout
    after = parse_audit_score(out2.splitlines())
    assert after.warned == score.warned - 1 and after.percent > score.percent                      # accepting changes the number the app shows
    subprocess.run([str(SUITE / "audit_events.py"), "--unaccept", LUKS], check=True, env=env, capture_output=True)
    back = parse_audit_score(subprocess.run([str(SUITE / "linux_security_audit.sh")], capture_output=True, text=True, env=env).stdout.splitlines())
    assert back == score                                                                           # revoking restores the original behaviour exactly


# ================================================== 8: the timer's own command line really runs and does its job
def unit_commands(text: str) -> list[str]:
    return [l.split("=", 1)[1].lstrip("-") for l in text.splitlines() if l.startswith(("ExecStart=", "ExecStartPost="))]


def test_the_commands_the_timers_run_exist_and_work(tmp_path):
    home = tmp_path / "h"
    (home / ".config/systemd/user").mkdir(parents=True)
    (tmp_path / "bin").mkdir()
    stub(tmp_path / "bin", "systemctl", "exit 0")
    env = {**os.environ, "HOME": str(home), "LG_HOME": str(tmp_path / "lg"), "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}
    for flag in ("--install", "--install-sensors"):
        assert subprocess.run([str(SUITE / "install_scheduler.sh"), flag], capture_output=True, text=True, env=env).returncode == 0
    units = home / ".config/systemd/user"
    sensors_unit = (units / "linuxguardian-sensors.service").read_text()
    scan_unit = (units / "linuxguardian-scan.service").read_text()
    for cmd in unit_commands(sensors_unit) + unit_commands(scan_unit):
        exe = cmd.split()[0].replace("%h", str(home))
        assert Path(exe).is_file() and os.access(exe, os.X_OK), f"unit runs {exe}, which is missing or not executable"
    assert "Nice=15" in sensors_unit and "IOSchedulingClass=idle" in sensors_unit and "Nice=10" in scan_unit      # stays out of your way
    timer = (units / "linuxguardian-sensors.timer").read_text()
    assert "OnUnitActiveSec=5min" in timer and "OnBootSec=2min" in timer
    # run the sensors unit's exact command lines the way systemd would (as you, no terminal, a tiny environment)
    sandbox = {"HOME": str(home), "LG_HOME": str(tmp_path / "lg"), "PATH": "/usr/bin:/bin", "LG_SETUID_ROOTS": str(tmp_path / "su"), "LG_APP_ROOT": str(tmp_path / "app")}
    (tmp_path / "su").mkdir()
    (tmp_path / "app").mkdir()
    for cmd in unit_commands(sensors_unit):
        r = subprocess.run(cmd.split(), capture_output=True, text=True, env=sandbox, timeout=90)
        assert r.returncode == 0, (cmd, r.stderr[-300:])
    assert (tmp_path / "lg" / "state" / "sensors.json").is_file()
    assert json.loads((tmp_path / "lg" / "state" / "sensors.json").read_text()).get("last_run")


# ===================================== 10: a configuration change changes what actually runs
def test_the_allow_list_changes_what_the_sensors_report(box, monkeypatch):
    learn(box, monkeypatch)
    add_proc(box, 7, "/opt/vendor/agent", ["/opt/vendor/agent"])
    (box / "ss.out").write_text(ss_line("agent", 7, "8.8.8.8", 443))
    sn.run_once()
    assert [e["event"] for e in sensor_events(box)] == ["new_outbound_program"]
    assert sn.allow_path_entry("/opt/other/")
    add_proc(box, 8, "/opt/other/tool", ["/opt/other/tool"])
    (box / "ss.out").write_text(ss_line("tool", 8, "8.8.4.4", 443))
    at(monkeypatch, 4 * DAY + 600)
    before = len(sensor_events(box))
    sn.run_once()
    assert len(sensor_events(box)) == before                                                       # now expected: stays quiet


def test_turning_notifications_off_changes_the_runtime_decision(box, popups, monkeypatch):
    learn(box, monkeypatch)
    provoke(box, "dropper")
    sn.run_once()
    notify_events.set_enabled(False)
    assert popups.now() == 0
    notify_events.set_enabled(True)
    assert popups.now() == 0                                                                       # nothing queued up to be announced late


def test_the_scan_exclusions_come_from_the_config_file(tmp_path):
    """A setting in ~/.linuxguardian/config reaches the command ClamAV is actually given."""
    for d in ("home", "bin", "lg"):
        (tmp_path / d).mkdir()
    (tmp_path / "lg").chmod(0o700)
    argv_log = tmp_path / "argv.log"
    stub(tmp_path / "bin", "clamscan", f'printf "%s\\n" "$*" >> "{argv_log}"\nexit 0')
    for n in ("rkhunter", "freshclam", "clamdscan"):
        stub(tmp_path / "bin", n, "exit 1" if n == "clamdscan" else "exit 0")
    (tmp_path / "lg" / "config").write_text("LG_CLAM_EXCLUDE_DIRS_QUICK='^/my/special/folder'\n")
    (tmp_path / "lg" / "config").chmod(0o600)
    env = {**os.environ, "HOME": str(tmp_path / "home"), "LG_HOME": str(tmp_path / "lg"), "PATH": f"{tmp_path / 'bin'}:/usr/bin:/bin"}
    subprocess.run([str(SUITE / "linux_guardian.sh"), "--scan", "--quick"], capture_output=True, text=True, env=env, timeout=60)
    assert "^/my/special/folder" in argv_log.read_text()


# ======================================= 11: one failing part never takes the rest down, and the failure is visible
def test_a_failing_sensor_is_reported_while_the_others_keep_working(box, monkeypatch):
    learn(box, monkeypatch)
    provoke(box, "dropper")
    monkeypatch.setitem(sn.SENSORS, "usb", lambda ctx: (_ for _ in ()).throw(RuntimeError("usb driver exploded")))
    r = sn.run_once()
    assert r["sensors"]["usb"]["ok"] is False and "usb driver exploded" in r["sensors"]["usb"]["error"]
    assert r["sensors"]["processes"]["ok"] and any(e["event"] == "proc_from_tmp" for e in sensor_events(box))
    status = sn.status()
    assert next(s for s in status["sensors"] if s["name"] == "usb")["ok"] is False                  # the problem reaches what the UI shows


def test_a_sensor_that_cannot_work_here_says_why_in_plain_words(box, monkeypatch):
    monkeypatch.setenv("LG_AUTH_LOG", str(box / "no-such-log"))
    r = sn.run_once()
    assert r["sensors"]["auth"]["ok"] is False and "adm" in r["sensors"]["auth"]["error"]


def test_events_flow_from_a_shell_script_into_the_timeline_with_the_right_kind(tmp_path):
    inc = tmp_path / "lg" / "incidents"
    inc.mkdir(parents=True)
    env = {**os.environ, "HOME": str(tmp_path), "LG_HOME": str(tmp_path / "lg")}
    subprocess.run(["bash", "-c", f'source "{SUITE}/config.sh"; source "{SUITE}/utils.sh"; lg_record_incident malware critical "ClamAV found 2 infected file(s) under /home/me"; '
                    'lg_record_incident process info "Killed PID 5 with SIGTERM"; lg_record_incident rootkit warning "rkhunter reported warnings"'], check=True, env=env)
    kinds = {e.message.split(" ")[0]: e.kind for e in timeline.load_entries(inc)}
    assert kinds == {"ClamAV": "incident", "Killed": "information", "rkhunter": "finding"}
    assert notify_events.worth_a_popup(next(e for e in timeline.load_entries(inc) if e.category == "malware"))

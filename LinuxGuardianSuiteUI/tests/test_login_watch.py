"""Login watch and the 2026-10-15 lessons: slow logins are noticed and tied to LinuxGuardian's own changes, loopback IPv6
stays on, the firewall's IPv6 switch is never offered on top of it, background runs never poke sudo, and alerts that
can't reach the desktop yet aren't lost."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "LinuxGuardianSuite"
sys.path.insert(0, str(SUITE))

import hardening  # noqa: E402
import login_watch as lw  # noqa: E402
import notify_events as ne  # noqa: E402

# Shapes of real `journalctl -o short-unix --grep ...` lines from the affected laptop.
T0 = float(int(time.time()) - 3600)


def journal(*pairs: tuple[float, str]) -> str:
    out = []
    for ts, what in pairs:
        if what == "setup":
            out.append(f"{ts:.6f} scythe /usr/libexec/gdm-x-session[5061]: /etc/gdm3/Xsession: Beginning session setup...")
        else:
            out.append(f"{ts:.6f} scythe gnome-shell[6266]: Running GNOME Shell (using mutter 42.9) as a X11 window and compositing manager")
    return "\n".join(out) + "\n"


@pytest.fixture()
def lg(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    j = tmp_path / "journal.txt"
    monkeypatch.setenv("LG_LOGIN_JOURNAL", str(j))
    return j


# ---------------------------------------------------------------- timing logins
def test_the_greeter_shell_is_ignored_and_each_login_is_paired_with_the_next_shell():
    text = journal((T0 - 13, "shell"), (T0, "setup"), (T0 + 136.2, "shell"), (T0 + 600, "setup"), (T0 + 603.5, "shell"))
    assert lw.parse_logins(text) == [{"start": T0, "seconds": 136.2}, {"start": T0 + 600, "seconds": 3.5}]


def test_a_login_that_never_finished_is_not_paired_with_the_next_boot():
    text = journal((T0, "setup"), (T0 + 25_000, "setup"), (T0 + 25_002, "shell"), (T0 + 30_000, "setup"))
    logins = lw.parse_logins(text)
    assert [entry["seconds"] for entry in logins] == [None, 2.0, None]
    text = journal((T0, "setup"), (T0 + 44_289, "shell"))
    assert lw.parse_logins(text)[0]["seconds"] is None                    # a shell hours later belongs to something else


def test_a_slow_login_is_reported_once_with_the_changes_made_since_the_last_normal_one(lg):
    lw.mark_change("Hardening applied: ufw_ipv6", "linux_hardening.sh --undo ufw_ipv6", when=T0 - 50)
    lw.mark_change("Firewall rule added", "sudo ufw delete allow 22", when=T0 - 5000)      # before the normal login: not a suspect
    lg.write_text(journal((T0 - 600, "setup"), (T0 - 596, "shell"), (T0, "setup"), (T0 + 135, "shell")))
    state: dict = {}
    [f] = lw.run(state)
    assert f["severity"] == "warning" and f["event"] == "slow_login" and "135 seconds" in f["message"]
    assert "Hardening applied: ufw_ipv6" in f["message"] and "linux_hardening.sh --undo ufw_ipv6" in f["message"]
    assert "Firewall rule added" not in f["message"] and "took 4 s" in f["message"]
    assert lw.run(state) == []                                              # judged once, never again


def test_slow_logins_with_no_changes_of_ours_say_the_cause_is_elsewhere(lg):
    lg.write_text(journal((T0, "setup"), (T0 + 134, "shell")))
    [f] = lw.run({})
    assert "no system changes in the week before" in f["message"]


def test_a_change_just_before_the_last_normal_login_is_still_named(lg):
    # Changed on day 0, a normal login the same day (the change waits for a reboot), slow from the next boot on.
    lw.mark_change("Hardening applied: ufw_ipv6", "linux_hardening.sh --undo ufw_ipv6", when=T0 - 2000)
    lg.write_text(journal((T0 - 1000, "setup"), (T0 - 999.6, "shell"), (T0, "setup"), (T0 + 134, "shell")))
    [f] = lw.run({})
    assert "only take effect after a reboot" in f["message"] and "--undo ufw_ipv6" in f["message"]


def test_hardening_fixes_from_before_the_ledger_are_suspects_too(lg):
    state = Path(os.environ["LG_HOME"]) / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "hardening_undo.json").write_text(json.dumps({"ufw_ipv6": {"applied": T0 - 100, "ipv6": "no"}, "vino_off": {"applied": T0 - 90}}))
    lg.write_text(journal((T0, "setup"), (T0 + 136, "shell")))
    [f] = lw.run({})
    assert "linux_hardening.sh --undo ufw_ipv6" in f["message"] and "hardening.py --undo vino_off" in f["message"]


def test_a_morning_of_slow_logins_is_one_story_and_fast_logins_are_quiet(lg):
    lg.write_text(journal(*[p for i in range(4) for p in ((T0 + i * 600, "setup"), (T0 + i * 600 + 136, "shell"))]))
    findings = lw.run({})
    assert len(findings) == 1 and str(int(T0 + 1800)) in findings[0]["key"]
    lg.write_text(journal((T0, "setup"), (T0 + 3, "shell")))
    assert lw.run({}) == []


def test_old_slow_logins_are_learned_but_not_reported(lg):
    old = time.time() - 10 * 86400
    lg.write_text(journal((old, "setup"), (old + 140, "shell")))
    state: dict = {}
    assert lw.run(state) == [] and state["logins_judged"]


def test_mark_change_keeps_the_login_time_before_it_as_the_baseline(lg):
    lg.write_text(journal((T0, "setup"), (T0 + 4.2, "shell")))
    entry = lw.mark_change("Firewall turned ON from LinuxGuardian", "linux_firewall.sh --disable")
    assert entry["login_before"] == 4.2 and lw.load_ledger()[-1]["undo"] == "linux_firewall.sh --disable"


def test_cli_check_and_mark_change(lg, tmp_path):
    lg.write_text(journal((T0, "setup"), (T0 + 136, "shell")))
    env = dict(os.environ)
    r = subprocess.run([sys.executable, str(SUITE / "login_watch.py"), "--check"], capture_output=True, text=True, env=env)
    assert r.returncode == 0 and "SLOW" in r.stdout
    r = subprocess.run([sys.executable, str(SUITE / "login_watch.py"), "--mark-change", "x", "--undo", "y"], capture_output=True, text=True, env=env)
    assert r.returncode == 0 and lw.load_ledger()[-1]["what"] == "x"


# ---------------------------------------------------------------- loopback IPv6
@pytest.fixture()
def sysfs(tmp_path, monkeypatch):
    lo = tmp_path / "sys" / "net" / "ipv6" / "conf" / "lo"
    lo.mkdir(parents=True)
    monkeypatch.setenv("LG_PROC_SYS", str(tmp_path / "sys"))
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    monkeypatch.setenv("LG_LOOPBACK_PROBE", "refused")
    default = tmp_path / "ufw-default"
    monkeypatch.setenv("LG_UFW_DEFAULT", str(default))
    return {"lo": lo / "disable_ipv6", "default": default}


def test_loopback_ipv6_off_is_flagged_with_a_fix(sysfs):
    sysfs["lo"].write_text("1\n")
    c = hardening.check_loopback_ipv6()
    assert c["state"] == "attention" and [f["id"] for f in c["fixes"]] == ["lo_ipv6"] and c["fixes"][0]["kind"] == "root"


def test_a_hanging_loopback_is_flagged_even_when_the_setting_looks_right(sysfs, monkeypatch):
    sysfs["lo"].write_text("0\n")
    monkeypatch.setenv("LG_LOOPBACK_PROBE", "timeout")
    assert hardening.check_loopback_ipv6()["state"] == "attention"
    monkeypatch.setenv("LG_LOOPBACK_PROBE", "refused")
    assert hardening.check_loopback_ipv6()["state"] == "ok"


def test_the_firewall_ipv6_switch_is_never_offered_while_loopback_ipv6_is_off(sysfs):
    sysfs["lo"].write_text("1\n")
    sysfs["default"].write_text("IPV6=no\n")
    c = hardening.check_firewall_ipv6()
    assert c["state"] == "attention" and c["fixes"] == [] and "loopback" in c["summary"].lower()
    sysfs["default"].write_text("IPV6=yes\n")
    assert "can't load" in hardening.check_firewall_ipv6()["summary"]


def test_lo_ipv6_records_what_it_replaced_for_undo(sysfs):
    sysfs["lo"].write_text("1\n")
    assert hardening.snapshot("lo_ipv6") == {"lo": 1}
    hardening.remember("lo_ipv6", hardening.snapshot("lo_ipv6"))
    assert hardening.undo_args("lo_ipv6") == ["1"]


def test_the_real_loopback_probe_answers_quickly():
    t = time.monotonic()
    assert hardening.loopback_probe(timeout=2.0) in ("refused", "open", "timeout", "unavailable")
    assert time.monotonic() - t < 3


# ---------------------------------------------------------------- background runs never poke sudo
def test_the_audit_never_calls_sudo_without_a_terminal(tmp_path):
    b = tmp_path / "bin"
    b.mkdir()
    log = tmp_path / "sudo.log"
    s = b / "sudo"
    s.write_text(f'#!/bin/sh\necho "$*" >> "{log}"\nexit 1\n')
    s.chmod(s.stat().st_mode | stat.S_IEXEC)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", LG_HOME=str(tmp_path / "lg"))
    r = subprocess.run(["bash", str(SUITE / "linux_security_audit.sh")], stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=120)
    assert "Sudo policy could not be verified" in r.stdout
    assert not log.exists(), "sudo was called from a non-interactive run (it logs 'conversation failed')"


# ---------------------------------------------------------------- alerts that can't reach the desktop yet
def test_an_alert_raised_before_the_desktop_is_up_is_sent_later_not_lost(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "home"))
    (tmp_path / "home" / "incidents").mkdir(parents=True)
    calls = tmp_path / "calls.log"
    stub = tmp_path / "notify-send"
    stub.write_text(f'#!/bin/sh\necho "$*" >> "{calls}"\n')
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("LG_NOTIFY_CMD", str(stub))
    now = 1_800_000_000.0
    ne.run_send(now)
    rec = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now + 10)), "category": "sensor", "severity": "warning",
           "message": "Logging in took 136 seconds"}
    (tmp_path / "home" / "incidents" / "a.json").write_text(json.dumps(rec))
    monkeypatch.setattr(ne, "notifications_ready", lambda: False)
    assert ne.run_send(now + 20) == 0 and not calls.exists()
    monkeypatch.setattr(ne, "notifications_ready", lambda: True)
    assert ne.run_send(now + 320) == 1 and "136 seconds" in calls.read_text()
    assert ne.run_send(now + 620) == 0


def test_the_logins_sensor_learns_on_its_first_run_and_reports_after(lg):
    import sensors

    lg.write_text(journal((T0, "setup"), (T0 + 136, "shell")))
    state: dict = {}
    assert sensors.sensor_logins(sensors.Ctx(state, time.time(), True, True, {})) == []
    lg.write_text(journal((T0, "setup"), (T0 + 136, "shell"), (T0 + 900, "setup"), (T0 + 1036, "shell")))
    [f] = sensors.sensor_logins(sensors.Ctx(state, time.time(), False, True, {}))
    assert f.event == "slow_login" and f.severity == "warning"

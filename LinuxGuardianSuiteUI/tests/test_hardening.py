"""Hardening checks and fixes against a fake laptop: states, previews, apply, and a faithful undo."""
from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import hardening as hd  # noqa: E402

FAKE_GS = ROOT / "tests" / "helpers" / "fake_gsettings.py"

GS_WEAK = {
    "org.gnome.Vino prompt-enabled": "false", "org.gnome.Vino require-encryption": "false",
    "org.gnome.Vino network-interface": "''", "org.gnome.Vino vnc-password": "'c2VjcmV0'",
    "org.gnome.desktop.screensaver lock-enabled": "false", "org.gnome.desktop.session idle-delay": "uint32 0",
    "org.gnome.desktop.notifications show-in-lock-screen": "true",
}
GS_GOOD = {**GS_WEAK, "org.gnome.Vino prompt-enabled": "true", "org.gnome.Vino require-encryption": "true", "org.gnome.Vino vnc-password": "''",
           "org.gnome.desktop.screensaver lock-enabled": "true", "org.gnome.desktop.session idle-delay": "uint32 300",
           "org.gnome.desktop.notifications show-in-lock-screen": "false"}


def stub(bindir: Path, name: str, body: str) -> None:
    p = bindir / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


@pytest.fixture()
def box(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".config" / "autostart").mkdir(parents=True)
    b = tmp_path / "bin"
    b.mkdir()
    gs = tmp_path / "gs.json"
    gs.write_text(json.dumps(GS_WEAK))
    sysd = tmp_path / "sys"
    for k, v in {"net.ipv4.conf.all.send_redirects": 1, "net.ipv4.tcp_syncookies": 1, "kernel.dmesg_restrict": 1}.items():
        f = sysd / k.replace(".", "/")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"{v}\n")
    (tmp_path / "ufw-default").write_text('IPV6=no\nDEFAULT_INPUT_POLICY="DROP"\n')
    (tmp_path / "ufw.conf").write_text("ENABLED=yes\nLOGLEVEL=low\n")
    (tmp_path / "gdm.conf").write_text("[daemon]\n#  AutomaticLoginEnable = true\n")
    (tmp_path / "apparmor").write_text("Y\n")
    stub(b, "gsettings", f'exec python3 "{FAKE_GS}" "$@"')
    stub(b, "ss", 'cat "$SS_OUT" 2>/dev/null; exit 0')
    stub(b, "pgrep", 'cat "$PGREP_OUT" 2>/dev/null; [ -s "$PGREP_OUT" ]')
    stub(b, "ip", 'case "$*" in *"-6 addr"*) echo "    inet6 2001:db8::5/64 scope global";; *"link show"*) echo "3: tailscale0: <UP>";; esac')
    stub(b, "lsblk", "printf 'TYPE\\ndisk\\npart\\n'")
    stub(b, "mokutil", "echo 'SecureBoot disabled'")
    stub(b, "systemctl", '''case "$*" in
  *is-enabled*) cat "$TIMER_STATE" 2>/dev/null || echo disabled ;;
  *"enable --now"*) echo enabled > "$TIMER_STATE" ;;
  *"disable --now"*) echo disabled > "$TIMER_STATE" ;;
esac
exit 0''')
    stub(b, "resolvectl", "echo 'Link 2 (w)'; echo '    Protocols: +DefaultRoute -DNSOverTLS'")
    monkeypatch.setenv("PATH", f"{b}:{os.environ['PATH']}")
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    monkeypatch.setenv("LG_HARDEN_HOME", str(home))
    monkeypatch.setenv("FAKE_GSETTINGS", str(gs))
    monkeypatch.setenv("LG_PROC_SYS", str(sysd))
    monkeypatch.setenv("LG_UFW_DEFAULT", str(tmp_path / "ufw-default"))
    monkeypatch.setenv("LG_UFW_CONF", str(tmp_path / "ufw.conf"))
    monkeypatch.setenv("LG_GDM_CONF", str(tmp_path / "gdm.conf"))
    monkeypatch.setenv("LG_APPARMOR", str(tmp_path / "apparmor"))
    monkeypatch.setenv("SS_OUT", str(tmp_path / "ss.out"))
    monkeypatch.setenv("TIMER_STATE", str(tmp_path / "timer.state"))
    monkeypatch.setenv("HOME", str(home))                      # install_scheduler.sh writes under $HOME: keep it in the sandbox
    monkeypatch.setenv("PGREP_OUT", str(tmp_path / "pgrep.out"))
    monkeypatch.delenv("FAKE_GSETTINGS_FAIL", raising=False)
    return tmp_path


def by_id(cid: str) -> dict:
    return {c["id"]: c for c in hd.collect()}[cid]


def gs_now(box: Path) -> dict:
    return json.loads((box / "gs.json").read_text())


def listen_on(box: Path, addr: str) -> None:
    (box / "ss.out").write_text(f"LISTEN 0 5 {addr}:5900 0.0.0.0:*\n")


VINO_DESKTOP = "[Desktop Entry]\nName=Desktop Sharing\nExec=/usr/libexec/vino-server --sm-disable\nType=Application\n"


# -------------------------------------------------------------- screen sharing
def test_screen_sharing_off_is_ok(box):
    assert by_id("screen_sharing")["state"] == "ok"


def test_screen_sharing_on_everywhere_with_no_approval_is_attention_and_never_prints_the_password(box):
    (box / "home/.config/autostart/vino-server.desktop").write_text(VINO_DESKTOP)
    listen_on(box, "0.0.0.0")
    c = by_id("screen_sharing")
    assert c["state"] == "attention" and "Wi-Fi" in c["summary"] and "base64" in c["summary"]
    assert "c2VjcmV0" not in json.dumps(c) and "secret" not in json.dumps(c).lower().replace("secure", "")
    assert {f["id"] for f in c["fixes"]} == {"vino_off", "vino_prompt", "vino_tailscale"}
    assert [f["id"] for f in c["fixes"] if f["recommended"]] == ["vino_off"]


def test_with_approval_and_encryption_it_is_only_informational(box):
    (box / "gs.json").write_text(json.dumps(GS_GOOD))
    (box / "home/.config/autostart/vino-server.desktop").write_text(VINO_DESKTOP)
    listen_on(box, "0.0.0.0")
    assert by_id("screen_sharing")["state"] == "info"


def test_limited_to_tailscale_counts_as_ok(box):
    gs = {**GS_WEAK, "org.gnome.Vino network-interface": "'tailscale0'"}
    (box / "gs.json").write_text(json.dumps(gs))
    (box / "home/.config/autostart/vino-server.desktop").write_text(VINO_DESKTOP)
    listen_on(box, "100.67.88.80")
    assert by_id("screen_sharing")["state"] == "ok"


def test_vino_off_stops_it_removes_autostart_and_undo_restores_it(box, monkeypatch):
    af = box / "home/.config/autostart/vino-server.desktop"
    af.write_text(VINO_DESKTOP)
    victim = subprocess.Popen(["sleep", "60"])
    (box / "pgrep.out").write_text(f"{victim.pid}\n")
    listen_on(box, "0.0.0.0")
    killed = []
    monkeypatch.setattr(hd.os, "kill", lambda pid, sig: (killed.append(pid), (box / "pgrep.out").write_text(""), (box / "ss.out").write_text("")))
    monkeypatch.setattr(hd, "_start_vino", lambda: None)
    try:
        r = hd.apply("vino_off")
        assert r["ok"] and killed == [victim.pid] and not af.exists()
        assert hd.is_applied("vino_off")
        assert hd.undo("vino_off")["ok"] and af.read_text() == VINO_DESKTOP and not hd.is_applied("vino_off")
    finally:
        victim.kill()


def test_vino_prompt_sets_both_and_undo_restores_exact_previous_values(box):
    before = gs_now(box)
    r = hd.apply("vino_prompt")
    now = gs_now(box)
    assert r["ok"] and now["org.gnome.Vino prompt-enabled"] == "true" and now["org.gnome.Vino require-encryption"] == "true"
    assert hd.undo("vino_prompt")["ok"] and gs_now(box) == before


def test_a_failed_second_setting_rolls_the_first_back(box, monkeypatch):
    monkeypatch.setenv("FAKE_GSETTINGS_FAIL", "org.gnome.Vino require-encryption")
    before = gs_now(box)
    r = hd.apply("vino_prompt")
    assert not r["ok"] and gs_now(box) == before and not hd.is_applied("vino_prompt")


def test_vino_tailscale_is_verified_and_reverted_if_it_does_not_really_limit_the_listener(box, monkeypatch):
    (box / "home/.config/autostart/vino-server.desktop").write_text(VINO_DESKTOP)
    listen_on(box, "0.0.0.0")
    monkeypatch.setattr(hd, "_kill_vino", lambda: None)
    monkeypatch.setattr(hd, "_start_vino", lambda: None)                  # restart: it still listens everywhere
    monkeypatch.setattr(hd.time, "sleep", lambda s: None)
    before = gs_now(box)
    r = hd.apply("vino_tailscale")
    assert not r["ok"] and "put back" in r["messages"][0] and gs_now(box) == before


def test_vino_tailscale_succeeds_when_the_listener_really_narrows(box, monkeypatch):
    listen_on(box, "0.0.0.0")
    monkeypatch.setattr(hd, "_kill_vino", lambda: None)
    monkeypatch.setattr(hd, "_start_vino", lambda: listen_on(box, "100.67.88.80"))
    monkeypatch.setattr(hd.time, "sleep", lambda s: None)
    r = hd.apply("vino_tailscale")
    assert r["ok"] and "100.67.88.80" in r["messages"][0] and gs_now(box)["org.gnome.Vino network-interface"] == "'tailscale0'"


# ----------------------------------------------------------------- lock screen
def test_screen_lock_weak_then_fixed_then_undone(box):
    assert by_id("screen_lock")["state"] == "attention"
    assert hd.apply("screen_lock")["ok"]
    assert by_id("screen_lock")["state"] == "ok"
    assert hd.undo("screen_lock")["ok"] and by_id("screen_lock")["state"] == "attention"


def test_a_long_idle_delay_is_called_out(box):
    gs = {**GS_GOOD, "org.gnome.desktop.session idle-delay": "uint32 1800"}
    (box / "gs.json").write_text(json.dumps(gs))
    assert "30 minutes" in by_id("screen_lock")["summary"]


def test_lock_notifications(box):
    assert by_id("lock_notifications")["state"] == "attention"
    hd.apply("lock_notifications")
    assert by_id("lock_notifications")["state"] == "ok"


def test_unreadable_settings_say_unknown_not_ok(box):
    (box / "gs.json").write_text("{}")
    assert by_id("screen_lock")["state"] == "unknown" and by_id("lock_notifications")["state"] == "unknown"


def test_auto_login(box):
    assert by_id("auto_login")["state"] == "ok"                          # the line is commented out
    (box / "gdm.conf").write_text("[daemon]\nAutomaticLoginEnable = true\n")
    assert by_id("auto_login")["state"] == "attention"


# ------------------------------------------------------------------- firewall
def test_firewall_states(box):
    assert by_id("firewall")["state"] == "ok"
    (box / "ufw.conf").write_text("ENABLED=no\nLOGLEVEL=off\n")
    assert by_id("firewall")["state"] == "attention" and by_id("firewall_logging")["state"] == "attention"
    (box / "ufw-default").write_text('IPV6=no\nDEFAULT_INPUT_POLICY="ACCEPT"\n')
    (box / "ufw.conf").write_text("ENABLED=yes\n")
    assert "allows incoming connections" in by_id("firewall")["summary"]


def test_ipv6_unfiltered_is_flagged_only_when_ipv6_is_actually_there(box):
    c = by_id("firewall_ipv6")                                           # fake `ip` shows a global IPv6 address
    assert c["state"] == "attention" and c["fixes"][0]["id"] == "ufw_ipv6" and c["fixes"][0]["kind"] == "root"
    (box / "ufw-default").write_text("IPV6=yes\n")
    assert by_id("firewall_ipv6")["state"] == "ok"


# -------------------------------------------------------------------- kernel
def test_kernel_drift_lists_exactly_what_differs(box):
    c = by_id("kernel_settings")
    assert c["state"] == "attention" and "send_redirects: 1 → 0" in c["detail"] and "syncookies" not in c["detail"]
    assert c["fixes"][0]["id"] == "sysctl" and c["fixes"][0]["kind"] == "root"


def test_kernel_all_good(box):
    (box / "sys/net/ipv4/conf/all/send_redirects").write_text("0\n")
    assert by_id("kernel_settings")["state"] == "ok"


def test_ge_mode_accepts_stricter_values(box):
    f = box / "sys/kernel/kptr_restrict"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("2\n")
    (box / "sys/net/ipv4/conf/all/send_redirects").write_text("0\n")
    assert by_id("kernel_settings")["state"] == "ok"


def test_settings_that_break_vpns_and_debuggers_are_never_touched():
    assert "net.ipv4.conf.all.rp_filter" not in hd.SYSCTL_TARGETS and "kernel.yama.ptrace_scope" not in hd.SYSCTL_TARGETS


def test_snapshot_and_undo_args_roundtrip_for_the_root_scripts(box):
    snap = hd.snapshot("sysctl")
    assert snap["sysctl"]["net.ipv4.conf.all.send_redirects"] == 1
    hd.remember("sysctl", snap)
    args = hd.undo_args("sysctl")
    assert "net.ipv4.conf.all.send_redirects" in args and args[args.index("net.ipv4.conf.all.send_redirects") + 1] == "1"
    assert len(args) % 2 == 0


def test_undo_args_reject_anything_not_allow_listed(box):
    hd.remember("sysctl", {"sysctl": {"kernel.core_pattern": 1, "net.ipv4.tcp_syncookies": 1, "fs.protected_hardlinks": "rm -rf"}})
    assert hd.undo_args("sysctl") == ["net.ipv4.tcp_syncookies", "1"]
    hd.remember("ufw_logging", {"loglevel": "low; reboot"})
    assert hd.undo_args("ufw_logging") == []
    hd.remember("ufw_logging", {"loglevel": "medium"})
    assert hd.undo_args("ufw_logging") == ["medium"]


def test_root_fixes_refuse_to_run_without_the_privileged_path(box):
    r = hd.apply("sysctl")
    assert not r["ok"] and "password" in r["messages"][0]
    assert not hd.apply("rm_everything")["ok"]


# ------------------------------------------------------------------- secrets
def make_key(path: Path, encrypted: bool, mode: int) -> None:
    cipher = b"aes256-ctr" if encrypted else b"none"
    raw = b"openssh-key-v1\0" + len(cipher).to_bytes(4, "big") + cipher + b"\0" * 20
    path.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64.b64encode(raw).decode() + "\n-----END OPENSSH PRIVATE KEY-----\n")
    os.chmod(path, mode)


def test_ssh_key_encryption_detection(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    make_key(a, True, 0o600)
    make_key(b, False, 0o600)
    assert hd.ssh_key_encrypted(a) is True and hd.ssh_key_encrypted(b) is False
    (tmp_path / "c").write_text("hello")
    assert hd.ssh_key_encrypted(tmp_path / "c") is None
    (tmp_path / "d").write_text("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nxx\n-----END RSA PRIVATE KEY-----\n")
    assert hd.ssh_key_encrypted(tmp_path / "d") is True


def test_ssh_permissions_fix_and_undo(box):
    ssh = box / "home/.ssh"
    ssh.mkdir()
    os.chmod(ssh, 0o755)
    make_key(ssh / "id_ed25519", False, 0o644)
    c = by_id("ssh_keys")
    assert c["state"] == "attention" and any(f["id"] == "perms_ssh" for f in c["fixes"]) and "ssh-keygen -p" in c["advice"]
    assert hd.apply("perms_ssh")["ok"]
    assert stat.S_IMODE(os.stat(ssh).st_mode) == 0o700 and stat.S_IMODE(os.stat(ssh / "id_ed25519").st_mode) == 0o600
    assert hd.undo("perms_ssh")["ok"]
    assert stat.S_IMODE(os.stat(ssh).st_mode) == 0o755 and stat.S_IMODE(os.stat(ssh / "id_ed25519").st_mode) == 0o644


def test_a_private_unencrypted_key_is_information_not_an_emergency(box):
    ssh = box / "home/.ssh"
    ssh.mkdir()
    os.chmod(ssh, 0o700)
    make_key(ssh / "id_ed25519", False, 0o600)
    assert by_id("ssh_keys")["state"] == "info"


def test_public_keys_and_known_hosts_are_not_treated_as_secrets(box):
    ssh = box / "home/.ssh"
    ssh.mkdir()
    os.chmod(ssh, 0o700)
    (ssh / "id.pub").write_text("ssh-ed25519 AAAA")
    (ssh / "known_hosts").write_text("x")
    os.chmod(ssh / "id.pub", 0o644)
    os.chmod(ssh / "known_hosts", 0o644)
    assert by_id("ssh_keys")["state"] == "ok"


def test_credential_files_fix_and_undo(box):
    h = box / "home"
    (h / ".aws").mkdir()
    (h / ".aws/credentials").write_text("[default]")
    (h / ".netrc").write_text("machine x")
    (h / ".env").write_text("TOKEN=1")
    for p in (h / ".aws/credentials", h / ".netrc", h / ".env"):
        os.chmod(p, 0o644)
    c = by_id("secret_files")
    assert c["state"] == "attention" and "3 credential" in c["summary"]
    assert hd.apply("perms_secrets")["ok"] and by_id("secret_files")["state"] == "ok"
    assert hd.undo("perms_secrets")["ok"] and stat.S_IMODE(os.stat(h / ".netrc").st_mode) == 0o644


def test_symlinked_secret_files_are_not_chmoded_through_the_link(box):
    h = box / "home"
    target = box / "elsewhere"
    target.write_text("x")
    os.chmod(target, 0o644)
    (h / ".netrc").symlink_to(target)
    hd.apply("perms_secrets")
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o644


# ----------------------------------------------------------------- disk & misc
def test_disk_encryption_and_secure_boot_and_apparmor(box):
    assert by_id("disk_encryption")["state"] == "attention" and "reinstall" in by_id("disk_encryption")["advice"]
    assert by_id("secure_boot")["state"] == "info" and by_id("apparmor")["state"] == "ok"
    stub(box / "bin", "lsblk", "printf 'TYPE\\ndisk\\ncrypt\\n'")
    assert by_id("disk_encryption")["state"] == "ok"
    (box / "apparmor").write_text("N\n")
    assert by_id("apparmor")["state"] == "attention"


# ----------------------------------------------------------- engine behaviour
def test_a_crashing_check_does_not_hide_the_others(box, monkeypatch):
    monkeypatch.setattr(hd, "check_apparmor", lambda: 1 / 0)
    monkeypatch.setattr(hd, "CHECKS", tuple(hd.CHECKS[:-1]) + (hd.check_apparmor,))
    checks = hd.collect()
    assert len(checks) == len(hd.CHECKS) and checks[-1]["state"] == "unknown"


def test_every_check_has_plain_language_and_valid_state(box):
    for c in hd.collect():
        assert c["state"] in ("ok", "attention", "info", "unknown") and c["summary"] and c["title"]
        if c["state"] == "attention":
            assert c["fixes"] or c["advice"], c["id"]                  # nothing flags a problem without saying what to do
        for f in c["fixes"]:
            assert f["effect"] and f["kind"] in ("user", "root") and f["label"]


def test_score_counts_only_decidable_checks(box):
    s = hd.score(hd.collect())
    assert s["total"] == s["ok"] + s["attention"] and 0 <= s["percent"] <= 100


def test_gsettings_values_are_validated_before_they_reach_the_command(box):
    for bad in ("true; reboot", "$(id)", "'a'; b", "", "-x"):
        with pytest.raises(ValueError):
            hd.gs_set("org.gnome.Vino", "prompt-enabled", bad)


def test_applying_records_an_event_and_cli_roundtrip(box):
    r = subprocess.run([sys.executable, str(ROOT / "LinuxGuardianSuite" / "hardening.py"), "--apply", "lock_notifications"],
                       capture_output=True, text=True, env=os.environ)
    assert r.returncode == 0
    from events import read_events
    assert any("lock_notifications" in e["message"] for e in read_events(box / "lg" / "incidents"))
    out = subprocess.run([sys.executable, str(ROOT / "LinuxGuardianSuite" / "hardening.py"), "--check", "--json"], capture_output=True, text=True, env=os.environ)
    data = json.loads(out.stdout)
    assert data["score"]["total"] > 0 and {c["id"] for c in data["checks"]} >= {"screen_sharing", "firewall", "kernel_settings"}


# ------------------------------------------------------------------ daily protection
def test_scheduler_check_and_fix_and_undo(box):
    c = by_id("scheduler")
    assert c["state"] == "attention" and c["fixes"][0]["id"] == "scheduler" and c["fixes"][0]["kind"] == "user"
    assert any("no password" in line.lower() for line in c["fixes"][0]["effect"])
    r = hd.apply("scheduler")
    assert r["ok"] and by_id("scheduler")["state"] == "ok"
    unit = box / "home/.config/systemd/user/linuxguardian-scan.service"
    text = unit.read_text()
    assert "--scan --changed" in text and "Nice=10" in text and "IOSchedulingClass=idle" in text
    assert hd.undo("scheduler")["ok"] and by_id("scheduler")["state"] == "attention" and not unit.exists()


def test_scheduler_failure_is_reported_not_claimed(box, monkeypatch):
    monkeypatch.setattr(hd, "timer_enabled", lambda: False)             # the job installs but never becomes enabled
    r = hd.apply("scheduler")
    assert not r["ok"] and not hd.is_applied("scheduler")


def test_applied_changes_stay_undoable_after_the_check_turns_green(box):
    hd.apply("screen_lock")
    assert by_id("screen_lock")["state"] == "ok" and not by_id("screen_lock")["fixes"]
    applied = {a["id"]: a for a in hd.applied_fixes()}
    assert applied["screen_lock"]["label"] and applied["screen_lock"]["kind"] == "user"
    hd.undo("screen_lock")
    assert "screen_lock" not in {a["id"] for a in hd.applied_fixes()}


def test_every_fix_that_can_be_applied_has_a_label_for_the_undo_list():
    for fid in list(hd.USER_FIXES) + list(hd.ROOT_FIXES):
        assert fid in hd.FIX_LABELS, fid


# ------------------------------------------------------------------ live monitoring
def test_live_monitoring_check_fix_and_undo(box):
    c = by_id("live_monitoring")
    assert c["state"] == "attention" and c["fixes"][0]["id"] == "sensors_timer"
    assert any("never stops, blocks or changes" in line for line in c["fixes"][0]["effect"])
    r = hd.apply("sensors_timer")
    assert r["ok"] and by_id("live_monitoring")["state"] == "ok"
    unit = box / "home/.config/systemd/user/linuxguardian-sensors.timer"
    text = unit.read_text()
    assert "OnUnitActiveSec=5min" in text
    assert "sensors.py --run" in (box / "home/.config/systemd/user/linuxguardian-sensors.service").read_text()
    assert hd.undo("sensors_timer")["ok"] and by_id("live_monitoring")["state"] == "attention" and not unit.exists()


def test_live_monitoring_fix_reports_failure_honestly(box, monkeypatch):
    monkeypatch.setattr(hd, "sensors_timer_enabled", lambda: False)
    assert not hd.apply("sensors_timer")["ok"] and not hd.is_applied("sensors_timer")

#!/usr/bin/env python3
"""Hardening checklist: what is weak on this laptop, why it matters, and a previewed, reversible fix.

Every check reads the machine without root and says in plain words what it found. A check that can be fixed
offers one or more fixes; each fix shows exactly what it will change BEFORE you accept it, remembers what it
replaced, and can be undone. Fixes that need root are carried out by `linux_hardening.sh` (one password prompt,
fixed scripts); the rest run as you.

  hardening.py --check [--json|--text]
  hardening.py --preview FIX     what the fix would change
  hardening.py --apply FIX       run a no-root fix (root fixes go through linux_hardening.sh)
  hardening.py --undo FIX        put back what the fix replaced

Test hooks: LG_HOME, LG_HARDEN_HOME ($HOME), LG_PROC_SYS (/proc/sys), LG_UFW_DEFAULT, LG_UFW_CONF, LG_GDM_CONF,
LG_VINO_BIN; gsettings/ss/pgrep/ip/lsblk/mokutil are found on PATH.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

from events import lg_home, record_event  # noqa: E402

VINO = "org.gnome.Vino"
SCREENSAVER = "org.gnome.desktop.screensaver"
SESSION = "org.gnome.desktop.session"
NOTIFS = "org.gnome.desktop.notifications"

# key -> (target, mode). "eq": must equal target. "ge": at least target (a stricter setting is fine).
# rp_filter is deliberately absent: strict reverse-path filtering breaks routing when a VPN (Tailscale, Proton) is up.
# ptrace_scope is left alone: raising it breaks attaching a debugger (gdb, ROS tooling) to your own processes.
SYSCTL_TARGETS: dict[str, tuple[int, str]] = {
    "net.ipv4.conf.all.send_redirects": (0, "eq"), "net.ipv4.conf.default.send_redirects": (0, "eq"),
    "net.ipv4.conf.all.accept_redirects": (0, "eq"), "net.ipv4.conf.default.accept_redirects": (0, "eq"),
    "net.ipv6.conf.all.accept_redirects": (0, "eq"), "net.ipv6.conf.default.accept_redirects": (0, "eq"),
    "net.ipv4.conf.all.accept_source_route": (0, "eq"), "net.ipv4.conf.default.accept_source_route": (0, "eq"),
    "net.ipv6.conf.all.accept_source_route": (0, "eq"),
    "net.ipv4.tcp_syncookies": (1, "eq"), "net.ipv4.icmp_echo_ignore_broadcasts": (1, "eq"),
    "net.ipv4.icmp_ignore_bogus_error_responses": (1, "eq"),
    "kernel.dmesg_restrict": (1, "eq"), "kernel.kptr_restrict": (1, "ge"), "kernel.unprivileged_bpf_disabled": (1, "ge"),
    "fs.protected_hardlinks": (1, "eq"), "fs.protected_symlinks": (1, "eq"), "kernel.randomize_va_space": (2, "eq"),
}
SECRET_FILES = (".netrc", ".git-credentials", ".pypirc", ".npmrc", ".aws/credentials", ".docker/config.json",
                ".config/gh/hosts.yml", ".config/rclone/rclone.conf", ".kube/config", ".config/gcloud/credentials.db")
STATE_ORDER = {"attention": 0, "unknown": 1, "info": 2, "ok": 3}


# ----------------------------------------------------------------- environment
def home() -> Path:
    return Path(os.environ.get("LG_HARDEN_HOME", str(Path.home())))


def undo_path() -> Path:
    return lg_home() / "state" / "hardening_undo.json"


def _run(cmd: list[str], timeout: float = 10) -> tuple[int, str]:
    env = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    return p.returncode, p.stdout


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return None


# ------------------------------------------------------------------- gsettings
def gs_get(schema: str, key: str) -> str | None:
    rc, out = _run(["gsettings", "get", schema, key])
    return out.strip() if rc == 0 else None


def gs_set(schema: str, key: str, value: str) -> bool:
    if not re.fullmatch(r"true|false|(uint32 )?\d+|'[A-Za-z0-9_.\- ]*'|\[('[A-Za-z0-9_.\-]*'(, )?)*\]", value):
        raise ValueError(f"refusing odd gsettings value: {value!r}")
    return _run(["gsettings", "set", schema, key, value])[0] == 0


def gs_bool(raw: str | None) -> bool | None:
    return None if raw is None else raw.strip() == "true"


def gs_int(raw: str | None) -> int | None:
    m = re.search(r"(\d+)\s*$", raw or "")
    return int(m.group(1)) if m else None


# ------------------------------------------------------------------ undo store
def load_undo() -> dict:
    try:
        data = json.loads(undo_path().read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_undo(data: dict) -> None:
    p = undo_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.replace(p)


def remember(fix_id: str, record: dict) -> None:
    data = load_undo()
    data[fix_id] = {"applied": int(time.time()), **record}
    save_undo(data)


def forget(fix_id: str) -> None:
    data = load_undo()
    if data.pop(fix_id, None) is not None:
        save_undo(data)


def is_applied(fix_id: str) -> bool:
    return fix_id in load_undo()


# ------------------------------------------------------------------ small probes
def listeners(port: int = 5900) -> list[str]:
    """Local addresses something is listening on for this TCP port (['0.0.0.0', '::'] means 'everywhere')."""
    rc, out = _run(["ss", "-ltnH"])
    addrs = []
    for line in out.splitlines() if rc == 0 else []:
        cols = line.split()
        if len(cols) >= 4 and cols[3].rsplit(":", 1)[-1] == str(port):
            addrs.append(cols[3].rsplit(":", 1)[0].strip("[]"))
    return addrs


def is_wildcard(addr: str) -> bool:
    return addr in ("0.0.0.0", "::", "*", "")


def vino_pids() -> list[int]:
    rc, out = _run(["pgrep", "-u", str(os.getuid()), "-x", "vino-server"])
    return [int(x) for x in out.split()] if rc == 0 else []


def interface_exists(name: str) -> bool:
    return (Path("/sys/class/net") / name).exists() or name in _run(["ip", "-o", "link", "show"])[1]


def autostart_file() -> Path:
    return home() / ".config" / "autostart" / "vino-server.desktop"


def autostart_enabled() -> bool:
    text = read_text(autostart_file())
    return text is not None and not re.search(r"^Hidden=true\s*$", text, re.M)


def vino_command() -> list[str]:
    override = os.environ.get("LG_VINO_BIN")
    if override:
        return [override, "--sm-disable"]
    text = read_text(autostart_file()) or ""
    m = re.search(r"^Exec=(.+)$", text, re.M)
    return m.group(1).split() if m else ["/usr/libexec/vino-server", "--sm-disable"]


# =========================================================================== checks
def check(cid: str, group: str, title: str, state: str, summary: str, why: str = "", detail: str = "",
          fixes: list[dict] | None = None, advice: str = "") -> dict:
    return {"id": cid, "group": group, "title": title, "state": state, "summary": summary, "why": why,
            "detail": detail, "fixes": fixes or [], "advice": advice}


def fix(fid: str, label: str, kind: str, effect: list[str], recommended: bool = False, caution: str = "") -> dict:
    return {"id": fid, "label": label, "kind": kind, "effect": effect, "recommended": recommended, "caution": caution,
            "applied": is_applied(fid)}


def check_screen_sharing() -> dict:
    why = ("Screen Sharing lets someone on your network see and control your screen. The built-in server's login is a short "
           "password that is not encrypted, and by default nobody has to approve a connection.")
    addrs = listeners(5900)
    on = autostart_enabled() or bool(addrs) or bool(vino_pids())
    if not on:
        return check("screen_sharing", "Access", "Screen Sharing", "ok", "Screen Sharing is off.", why)
    prompt = gs_bool(gs_get(VINO, "prompt-enabled"))
    enc = gs_bool(gs_get(VINO, "require-encryption"))
    iface = (gs_get(VINO, "network-interface") or "''").strip("'")
    pw = (gs_get(VINO, "vnc-password") or "''").strip("'")
    everywhere = (not addrs) or any(is_wildcard(a) for a in addrs)
    notes = []
    if everywhere and not iface:
        notes.append("It listens on every network this laptop is on, including Wi-Fi.")
    if not prompt:
        notes.append("Nobody has to approve a connection.")
    if not enc:
        notes.append("The connection isn't encrypted.")
    if pw:
        notes.append("Its password is saved on this laptop in a form that is trivially reversible (base64, not encrypted).")
    detail = f"listening on: {', '.join(addrs) or 'not currently running'}; prompt={prompt}; encryption={enc}; interface='{iface}'"
    fixes = [fix("vino_off", "Turn Screen Sharing off", "user",
                 ["Stops the running Screen Sharing server.", "Removes its automatic start at login (a copy is kept so you can undo)."],
                 recommended=True)]
    if not (prompt and enc):
        fixes.append(fix("vino_prompt", "Keep it on, but ask me to approve and encrypt", "user",
                         [f"Approval prompt: {'on' if prompt else 'OFF'} → on", f"Require encryption: {'on' if enc else 'OFF'} → on"],
                         caution="Some VNC apps can't do encryption and will stop connecting."))
    if interface_exists("tailscale0") and not iface:
        fixes.append(fix("vino_tailscale", "Keep it on, but only reachable over Tailscale", "user",
                         ["Limits Screen Sharing to your Tailscale network (tailscale0), so your Wi-Fi/LAN can't reach it.",
                          "Restarts Screen Sharing and checks that it really is limited; undoes itself if it isn't."]))
    exposed = everywhere and not iface
    weak = not (prompt and enc)
    state = "attention" if (exposed and weak) else "info" if exposed else "ok"
    headline = "Screen Sharing is ON." + (" " + " ".join(notes) if notes else " It looks locked down.")
    return check("screen_sharing", "Access", "Screen Sharing", state, headline, why, detail, fixes if state != "ok" else [])


def check_screen_lock() -> dict:
    why = "A lock screen is what stands between a passer-by (or a thief with your open laptop) and everything you're logged into."
    lock = gs_bool(gs_get(SCREENSAVER, "lock-enabled"))
    idle = gs_int(gs_get(SESSION, "idle-delay"))
    if lock is None or idle is None:
        return check("screen_lock", "Access", "Automatic screen lock", "unknown", "Couldn't read the lock-screen settings.", why)
    problems = []
    if not lock:
        problems.append("the screen doesn't lock when it blanks")
    if idle == 0:
        problems.append("the screen never blanks by itself")
    elif idle > 600:
        problems.append(f"it takes {idle // 60} minutes to blank")
    if not problems:
        return check("screen_lock", "Access", "Automatic screen lock", "ok", f"The screen locks after {idle // 60 or 1} minute(s) of inactivity.", why)
    return check("screen_lock", "Access", "Automatic screen lock", "attention", "Your screen lock is weak: " + ", ".join(problems) + ".", why,
                 fixes=[fix("screen_lock", "Lock after 5 minutes", "user",
                            [f"Lock when the screen blanks: {'on' if lock else 'OFF'} → on",
                             f"Blank the screen after: {'never' if idle == 0 else f'{idle // 60} min'} → 5 min"], recommended=True)])


def check_lock_notifications() -> dict:
    why = "Notifications on the lock screen can show messages, codes and email subjects to anyone who walks past."
    shown = gs_bool(gs_get(NOTIFS, "show-in-lock-screen"))
    if shown is None:
        return check("lock_notifications", "Access", "Notifications on the lock screen", "unknown", "Couldn't read the setting.", why)
    if not shown:
        return check("lock_notifications", "Access", "Notifications on the lock screen", "ok", "Notification contents are hidden while locked.", why)
    return check("lock_notifications", "Access", "Notifications on the lock screen", "attention",
                 "Notification contents are visible on the lock screen.", why,
                 fixes=[fix("lock_notifications", "Hide notifications while locked", "user", ["Show on lock screen: on → off"], recommended=True)])


def check_auto_login() -> dict:
    why = "With automatic login, anyone who powers on the laptop is signed in as you with no password."
    text = read_text(Path(os.environ.get("LG_GDM_CONF", "/etc/gdm3/custom.conf"))) or ""
    on = re.search(r"^\s*AutomaticLoginEnable\s*=\s*(true|1)\s*$", text, re.M | re.I)
    if on:
        return check("auto_login", "Access", "Automatic login", "attention", "Automatic login is on.", why,
                     advice="Turn it off in Settings → Users → Automatic Login.")
    return check("auto_login", "Access", "Automatic login", "ok", "You sign in with a password.", why)


def check_firewall() -> dict:
    why = "The firewall decides which programs on your laptop other machines can talk to."
    default = read_text(Path(os.environ.get("LG_UFW_DEFAULT", "/etc/default/ufw"))) or ""
    conf = read_text(Path(os.environ.get("LG_UFW_CONF", "/etc/ufw/ufw.conf"))) or ""
    if not default and not conf:
        return check("firewall", "Network", "Firewall", "unknown", "ufw (Ubuntu's firewall) isn't installed or can't be read.", why,
                     advice="Install and turn it on: sudo apt install ufw && sudo ufw enable")
    enabled = re.search(r"^ENABLED=yes", conf, re.M | re.I) is not None
    deny_in = re.search(r'^DEFAULT_INPUT_POLICY="?(DROP|REJECT)', default, re.M) is not None
    if enabled and deny_in:
        return check("firewall", "Network", "Firewall", "ok", "The firewall is on and blocks unsolicited incoming connections.", why,
                     detail="Individual allow-rules can only be read with a password; see the Exposure tab.")
    if not enabled:
        return check("firewall", "Network", "Firewall", "attention", "The firewall is turned off.", why,
                     advice="Turn it on: sudo ufw enable (make sure SSH or other services you need are allowed first).")
    return check("firewall", "Network", "Firewall", "attention", "The firewall is on but allows incoming connections by default.", why,
                 advice="sudo ufw default deny incoming")


def _has_ipv6() -> bool:
    rc, out = _run(["ip", "-6", "addr", "show", "scope", "global"])
    return rc == 0 and "inet6" in out


def check_firewall_ipv6() -> dict:
    why = "If the firewall ignores IPv6, anything reachable over IPv6 skips every rule you set."
    default = read_text(Path(os.environ.get("LG_UFW_DEFAULT", "/etc/default/ufw")))
    if default is None:
        return check("firewall_ipv6", "Network", "Firewall covers IPv6", "unknown", "Couldn't read the firewall settings.", why)
    v6_on = re.search(r"^IPV6=yes", default, re.M | re.I) is not None
    if v6_on:
        return check("firewall_ipv6", "Network", "Firewall covers IPv6", "ok", "The firewall filters IPv6 as well as IPv4.", why)
    listening_v6 = [a for a in listeners(5900) if ":" in a] + [a for p in (22, 80, 443, 631, 8080) for a in listeners(p) if ":" in a]
    if not (_has_ipv6() or listening_v6):
        return check("firewall_ipv6", "Network", "Firewall covers IPv6", "info", "The firewall ignores IPv6, but this laptop has no IPv6 address right now.", why)
    return check("firewall_ipv6", "Network", "Firewall covers IPv6", "attention",
                 "The firewall is not filtering IPv6, so rules you set apply only to IPv4.", why,
                 detail="IPV6=no in /etc/default/ufw" + (f"; something listens on IPv6 ({', '.join(listening_v6)})" if listening_v6 else ""),
                 fixes=[fix("ufw_ipv6", "Make the firewall filter IPv6 too", "root",
                            ["Changes IPV6=no → IPV6=yes in /etc/default/ufw and reloads the firewall.", "Needs your password."], recommended=True,
                            caution="Allow-rules you made for IPv4 are mirrored for IPv6 automatically.")])


def check_firewall_logging() -> dict:
    why = "Without logging you can't tell what the firewall blocked, which makes attacks and mistakes invisible."
    conf = read_text(Path(os.environ.get("LG_UFW_CONF", "/etc/ufw/ufw.conf")))
    if conf is None:
        return check("firewall_logging", "Network", "Firewall logging", "unknown", "Couldn't read the firewall settings.", why)
    m = re.search(r"^LOGLEVEL=(\w+)", conf, re.M)
    level = m.group(1) if m else "unknown"
    if level in ("low", "medium", "high", "full", "on"):
        return check("firewall_logging", "Network", "Firewall logging", "ok", f"Blocked connections are logged (level: {level}).", why)
    return check("firewall_logging", "Network", "Firewall logging", "attention", "The firewall doesn't log what it blocks.", why,
                 fixes=[fix("ufw_logging", "Turn firewall logging on (low)", "root", [f"Logging: {level} → low", "Needs your password."], recommended=True)])


def sysctl_value(key: str) -> int | None:
    base = Path(os.environ.get("LG_PROC_SYS", "/proc/sys"))
    text = read_text(base / key.replace(".", "/"))
    try:
        return int(text.strip()) if text is not None else None
    except ValueError:
        return None


def sysctl_drift() -> list[tuple[str, int, int]]:
    """[(key, current, wanted)] for settings that exist on this kernel and aren't where they should be."""
    out = []
    for key, (target, mode) in SYSCTL_TARGETS.items():
        cur = sysctl_value(key)
        if cur is None:
            continue
        if (mode == "eq" and cur != target) or (mode == "ge" and cur < target):
            out.append((key, cur, target))
    return out


def check_kernel_settings() -> dict:
    why = ("A handful of kernel settings decide whether your laptop accepts forged routing messages, can be flooded with half-open "
           "connections, or leaks kernel addresses that help attackers. Ubuntu sets most of them well; some are left loose.")
    drift = sysctl_drift()
    if os.environ.get("LG_PROC_SYS") is None and not Path("/proc/sys").exists():
        return check("kernel_settings", "Network", "Kernel hardening", "unknown", "Couldn't read kernel settings.", why)
    if not drift:
        return check("kernel_settings", "Network", "Kernel hardening", "ok", "Kernel network and memory protections are set as recommended.", why)
    lines = [f"{k}: {c} → {t}" for k, c, t in drift]
    return check("kernel_settings", "Network", "Kernel hardening", "attention",
                 f"{len(drift)} kernel setting(s) are looser than recommended.", why, detail="\n".join(lines),
                 fixes=[fix("sysctl", "Apply the recommended kernel settings", "root", lines + ["Saved in /etc/sysctl.d, so it survives reboots. Needs your password."],
                            recommended=True, caution="Doesn't touch settings that VPNs (Tailscale, Proton) or debuggers rely on.")])


def check_dns() -> dict:
    why = "DNS lookups reveal every site you visit to whoever runs the resolver, unless they're encrypted or tunnelled."
    rc, out = _run(["resolvectl", "status"])
    if rc != 0:
        return check("dns_privacy", "Network", "DNS privacy", "unknown", "Couldn't read the DNS settings.", why)
    if re.search(r"^\s*Protocols:.*\+DNSOverTLS", out, re.M):
        return check("dns_privacy", "Network", "DNS privacy", "ok", "DNS lookups are encrypted (DNS over TLS).", why)
    return check("dns_privacy", "Network", "DNS privacy", "info",
                 "DNS lookups are sent in the clear to your network's resolver (normal; a VPN like Proton tunnels them).", why,
                 advice="If you don't always use a VPN, consider DNS over TLS in systemd-resolved.")


def ssh_key_encrypted(path: Path) -> bool | None:
    """True/False if we can tell whether a private key needs a passphrase, None if unreadable/unrecognised."""
    text = read_text(path)
    if not text:
        return None
    if "BEGIN OPENSSH PRIVATE KEY" in text:
        try:
            body = "".join(l for l in text.splitlines() if not l.startswith("-----"))
            raw = base64.b64decode(body)
            if not raw.startswith(b"openssh-key-v1\0"):
                return None
            n = int.from_bytes(raw[15:19], "big")
            return raw[19:19 + n] != b"none"
        except Exception:  # noqa: BLE001
            return None
    if "BEGIN" in text and "PRIVATE KEY" in text:
        if "ENCRYPTED" in text:
            return True
        return False
    return None


def _mode(path: Path) -> int | None:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None


def ssh_findings() -> tuple[list[tuple[Path, int, int]], list[Path]]:
    """([(path, current_mode, wanted_mode)], [unencrypted private keys])"""
    ssh = home() / ".ssh"
    loose: list[tuple[Path, int, int]] = []
    plain: list[Path] = []
    if not ssh.is_dir():
        return loose, plain
    m = _mode(ssh)
    if m is not None and m & 0o077:
        loose.append((ssh, m, 0o700))
    for p in sorted(ssh.iterdir()):
        if not p.is_file() or p.is_symlink() or p.suffix == ".pub" or p.name in ("known_hosts", "known_hosts.old", "authorized_keys", "config"):
            continue
        enc = ssh_key_encrypted(p)
        if enc is None:
            continue
        pm = _mode(p)
        if pm is not None and pm & 0o077:
            loose.append((p, pm, 0o600))
        if enc is False:
            plain.append(p)
    for name in ("config", "authorized_keys"):
        p = ssh / name
        pm = _mode(p)
        if p.is_file() and pm is not None and pm & 0o022:
            loose.append((p, pm, 0o600))
    return loose, plain


def secret_file_findings() -> list[tuple[Path, int, int]]:
    out = []
    h = home()
    candidates = [h / rel for rel in SECRET_FILES] + [p for p in h.glob(".env*") if p.is_file()] + [p for p in h.glob("*.pem") if p.is_file()]
    for p in candidates:
        if p.is_file() and not p.is_symlink():
            m = _mode(p)
            if m is not None and m & 0o077:
                out.append((p, m, 0o600))
    return out


def _fmt_mode(m: int) -> str:
    return format(m, "03o")


def check_ssh_keys() -> dict:
    why = "Anyone who can read your private SSH key can log in to everything it unlocks (your robots, GitHub, servers)."
    loose, plain = ssh_findings()
    if not (home() / ".ssh").is_dir():
        return check("ssh_keys", "Secrets", "SSH keys", "ok", "No SSH folder.", why)
    parts, fixes, advice = [], [], ""
    if loose:
        parts.append(f"{len(loose)} SSH file(s) can be read by other users")
        fixes.append(fix("perms_ssh", "Make my SSH files private", "user",
                         [f"{p.name or 'folder'}: {_fmt_mode(c)} → {_fmt_mode(w)}" for p, c, w in loose], recommended=True))
    if plain:
        parts.append(f"{len(plain)} private key(s) have no passphrase")
        advice = "Add a passphrase: ssh-keygen -p -f " + str(plain[0]).replace(str(home()), "~")
    if not parts:
        return check("ssh_keys", "Secrets", "SSH keys", "ok", "Your SSH files are private and your keys are passphrase-protected.", why)
    detail = "\n".join([f"{p}: mode {_fmt_mode(c)}" for p, c, _ in loose] + [f"{p}: no passphrase" for p in plain])
    return check("ssh_keys", "Secrets", "SSH keys", "attention" if loose else "info", "; ".join(parts) + ".", why, detail, fixes, advice)


def check_secret_files() -> dict:
    why = "Files like cloud credentials and API tokens are stored in plain text; other accounts or programs shouldn't be able to read them."
    found = secret_file_findings()
    if not found:
        return check("secret_files", "Secrets", "Token and credential files", "ok", "Your credential files are private.", why)
    lines = [f"{str(p).replace(str(home()), '~')}: {_fmt_mode(c)} → {_fmt_mode(w)}" for p, c, w in found]
    return check("secret_files", "Secrets", "Token and credential files", "attention",
                 f"{len(found)} credential file(s) can be read by other users.", why, "\n".join(lines),
                 [fix("perms_secrets", "Make my credential files private", "user", lines, recommended=True)])


def check_disk_encryption() -> dict:
    why = "If the laptop is lost or stolen, an unencrypted disk can be read by plugging it into another computer. A login password doesn't stop that."
    rc, out = _run(["lsblk", "-o", "TYPE"])
    if rc == 0 and "crypt" in out.split():
        return check("disk_encryption", "Disk & boot", "Disk encryption", "ok", "The disk is encrypted (LUKS).", why)
    return check("disk_encryption", "Disk & boot", "Disk encryption", "attention", "The disk is not encrypted.", why,
                 advice="This can't be switched on in place. Turn it on when you next reinstall Ubuntu (choose 'Encrypt the new Ubuntu "
                        "installation'), and until then keep sensitive things (SSH keys, tokens) minimal, set a BIOS/UEFI password, and keep backups.")


def check_secure_boot() -> dict:
    why = "Secure Boot stops tampered boot software from loading before your system starts."
    rc, out = _run(["mokutil", "--sb-state"])
    if rc != 0 and not out:
        return check("secure_boot", "Disk & boot", "Secure Boot", "unknown", "Couldn't read the Secure Boot state.", why)
    if "enabled" in out.lower() and "disabled" not in out.lower():
        return check("secure_boot", "Disk & boot", "Secure Boot", "ok", "Secure Boot is on.", why)
    return check("secure_boot", "Disk & boot", "Secure Boot", "info", "Secure Boot is off (common on machines with NVIDIA/CUDA or custom kernel modules).", why,
                 advice="Turning it on needs signed drivers; only worth it if you don't depend on unsigned modules.")


def timer_enabled() -> bool | None:
    if not shutil.which("systemctl"):
        return None
    rc, out = _run(["systemctl", "--user", "is-enabled", "linuxguardian-scan.timer"])
    return out.strip() == "enabled"


def check_scheduler() -> dict:
    why = ("Protection that only runs when you remember to open the app isn't protection. The daily job scans for malware, checks your "
           "important files, looks for newly exposed services, runs this audit and tells you if something new turns up.")
    on = timer_enabled()
    if on is None:
        return check("scheduler", "Defences", "Daily background protection", "unknown", "Couldn't read your user services.", why)
    if on:
        return check("scheduler", "Defences", "Daily background protection", "ok", "A daily check runs in the background and notifies you of anything new.", why)
    return check("scheduler", "Defences", "Daily background protection", "attention",
                 "Nothing runs in the background, so a problem can sit unnoticed until you open the app.", why,
                 fixes=[fix("scheduler", "Turn on daily background protection", "user",
                            ["Installs a daily job that runs as you (no password).",
                             "Scans files changed since the last scan, checks file integrity and exposure, runs this audit, sends notifications.",
                             "Runs at low priority so it stays out of the way."], recommended=True)])


def sensors_timer_enabled() -> bool | None:
    if not shutil.which("systemctl"):
        return None
    rc, out = _run(["systemctl", "--user", "is-enabled", "linuxguardian-sensors.timer"])
    return out.strip() == "enabled"


def check_live_monitoring() -> dict:
    why = ("The daily scan finds what is already there. Live monitoring looks every 5 minutes for what an attack does while it happens: "
           "guessed logins, programs running from /tmp, a new program phoning home, something adding itself to startup.")
    on = sensors_timer_enabled()
    if on is None:
        return check("live_monitoring", "Defences", "Live attack monitoring", "unknown", "Couldn't read your user services.", why)
    if on:
        return check("live_monitoring", "Defences", "Live attack monitoring", "ok", "The blue-team sensors run every 5 minutes and alert you to anything new.", why)
    return check("live_monitoring", "Defences", "Live attack monitoring", "attention",
                 "Nothing is watching for an attack as it happens.", why,
                 fixes=[fix("sensors_timer", "Turn on live monitoring", "user",
                            ["Installs a job that runs as you (no password) every 5 minutes.",
                             "Checks login history, running programs, new network behaviour, startup entries, accounts and USB devices.",
                             "Learns what's normal on this laptop first (3 days of quiet), then tells you about new, suspicious things.",
                             "Only observes: it never stops, blocks or changes anything."], recommended=True)])


def check_apparmor() -> dict:
    why = "AppArmor confines programs so a hacked app can't reach everything you can."
    text = read_text(Path(os.environ.get("LG_APPARMOR", "/sys/module/apparmor/parameters/enabled")))
    if text is not None and text.strip() == "Y":
        return check("apparmor", "Defences", "AppArmor", "ok", "AppArmor is running.", why)
    return check("apparmor", "Defences", "AppArmor", "attention" if text is not None else "unknown", "AppArmor isn't running.", why,
                 advice="sudo systemctl enable --now apparmor")


CHECKS = (check_screen_sharing, check_screen_lock, check_lock_notifications, check_auto_login, check_firewall, check_firewall_ipv6,
          check_firewall_logging, check_kernel_settings, check_dns, check_ssh_keys, check_secret_files, check_disk_encryption,
          check_secure_boot, check_apparmor, check_scheduler, check_live_monitoring)


def collect() -> list[dict]:
    results = []
    for fn in CHECKS:
        try:
            results.append(fn())
        except Exception as exc:  # noqa: BLE001 - one broken check must never hide the others
            results.append(check(fn.__name__.removeprefix("check_"), "Other", fn.__name__.removeprefix("check_").replace("_", " "),
                                 "unknown", f"This check failed to run ({type(exc).__name__}).", ""))
    return results


FIX_LABELS = {
    "vino_off": ("Turned Screen Sharing off", "user"), "vino_prompt": ("Screen Sharing asks for approval and encryption", "user"),
    "vino_tailscale": ("Screen Sharing limited to Tailscale", "user"), "screen_lock": ("Screen locks after 5 minutes", "user"),
    "lock_notifications": ("Notifications hidden on the lock screen", "user"), "perms_ssh": ("SSH files made private", "user"),
    "perms_secrets": ("Credential files made private", "user"), "scheduler": ("Daily background protection", "user"),
    "sensors_timer": ("Live attack monitoring", "user"),
    "sysctl": ("Recommended kernel settings", "root"), "ufw_ipv6": ("Firewall filters IPv6", "root"),
    "ufw_logging": ("Firewall logging on", "root"),
}


def applied_fixes() -> list[dict]:
    """Changes LinuxGuardian made that can still be undone (so Undo stays reachable after a check turns green)."""
    out = []
    for fid, rec in load_undo().items():
        if fid in FIX_LABELS:
            label, kind = FIX_LABELS[fid]
            out.append({"id": fid, "label": label, "kind": kind, "when": rec.get("applied", 0)})
    return sorted(out, key=lambda r: r["when"], reverse=True)


def score(checks: list[dict]) -> dict:
    ok = sum(c["state"] == "ok" for c in checks)
    bad = sum(c["state"] == "attention" for c in checks)
    return {"ok": ok, "attention": bad, "total": ok + bad, "percent": round(100 * ok / (ok + bad)) if ok + bad else 100}


# =========================================================================== fixes
def preview(fix_id: str) -> list[str]:
    for c in collect():
        for f in c["fixes"]:
            if f["id"] == fix_id:
                return f["effect"]
    if is_applied(fix_id):
        return ["Already applied. Undo puts back what it replaced."]
    return []


def _result(ok: bool, *messages: str) -> dict:
    return {"ok": ok, "messages": list(messages)}


def _kill_vino() -> None:
    for pid in vino_pids():
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    for _ in range(30):
        if not vino_pids():
            return
        time.sleep(0.1)


def _start_vino() -> None:
    try:
        subprocess.Popen(vino_command(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)  # noqa: S603
    except OSError:
        pass


def apply_vino_off() -> dict:
    f = autostart_file()
    text = read_text(f)
    record = {"autostart": text, "was_running": bool(vino_pids())}
    if text is not None:
        f.unlink()
    _kill_vino()
    remember("vino_off", record)
    for _ in range(20):
        if not listeners(5900):
            break
        time.sleep(0.1)
    if listeners(5900):
        return _result(False, "Screen Sharing is still listening. Turn it off in Settings → Sharing.")
    return _result(True, "Screen Sharing is off, and won't start at login.")


def undo_vino_off() -> dict:
    rec = load_undo().get("vino_off")
    if not rec:
        return _result(False, "Nothing to undo.")
    if rec.get("autostart") is not None:
        f = autostart_file()
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(rec["autostart"])
    if rec.get("was_running"):
        _start_vino()
    forget("vino_off")
    return _result(True, "Screen Sharing is back as it was.")


def _apply_gsettings(fix_id: str, settings: list[tuple[str, str, str]]) -> dict:
    prior = {}
    for schema, key, _new in settings:
        old = gs_get(schema, key)
        if old is None:
            return _result(False, f"Couldn't read {schema} {key}; nothing was changed.")
        prior[f"{schema} {key}"] = old
    remember(fix_id, {"gsettings": prior})
    for schema, key, new in settings:
        if not gs_set(schema, key, new):
            undo_gsettings(fix_id)
            return _result(False, f"Couldn't change {key}; everything was put back.")
    return _result(True, "Done.")


def undo_gsettings(fix_id: str) -> dict:
    rec = load_undo().get(fix_id)
    if not rec:
        return _result(False, "Nothing to undo.")
    for sk, old in rec.get("gsettings", {}).items():
        schema, key = sk.split(" ", 1)
        gs_set(schema, key, old)
    forget(fix_id)
    return _result(True, "Put back the previous settings.")


def apply_vino_prompt() -> dict:
    return _apply_gsettings("vino_prompt", [(VINO, "prompt-enabled", "true"), (VINO, "require-encryption", "true")])


def apply_vino_tailscale() -> dict:
    if not interface_exists("tailscale0"):
        return _result(False, "Tailscale isn't running on this laptop (no tailscale0 interface).")
    res = _apply_gsettings("vino_tailscale", [(VINO, "network-interface", "'tailscale0'")])
    if not res["ok"]:
        return res
    _kill_vino()
    _start_vino()
    addrs: list[str] = []
    for _ in range(40):
        addrs = listeners(5900)
        if addrs:
            break
        time.sleep(0.1)
    if not addrs or any(is_wildcard(a) for a in addrs):
        undo_gsettings("vino_tailscale")
        _kill_vino()
        _start_vino()
        return _result(False, "This version of Screen Sharing still listens on every network with that setting, so it was put back. "
                              "Use 'Turn Screen Sharing off' or 'ask me to approve and encrypt' instead.")
    return _result(True, f"Screen Sharing now only listens on {', '.join(addrs)} (your Tailscale address).")


def apply_screen_lock() -> dict:
    return _apply_gsettings("screen_lock", [(SCREENSAVER, "lock-enabled", "true"), (SESSION, "idle-delay", "uint32 300")])


def apply_lock_notifications() -> dict:
    return _apply_gsettings("lock_notifications", [(NOTIFS, "show-in-lock-screen", "false")])


def _apply_modes(fix_id: str, items: list[tuple[Path, int, int]]) -> dict:
    if not items:
        return _result(True, "Nothing needed changing.")
    remember(fix_id, {"modes": {str(p): cur for p, cur, _w in items}})
    done = 0
    for p, _cur, want in items:
        try:
            os.chmod(p, want)
            done += 1
        except OSError:
            pass
    return _result(done == len(items), f"Made {done} of {len(items)} file(s) private.")


def apply_perms_ssh() -> dict:
    return _apply_modes("perms_ssh", ssh_findings()[0])


def apply_perms_secrets() -> dict:
    return _apply_modes("perms_secrets", secret_file_findings())


def undo_modes(fix_id: str) -> dict:
    rec = load_undo().get(fix_id)
    if not rec:
        return _result(False, "Nothing to undo.")
    for path, mode in rec.get("modes", {}).items():
        try:
            os.chmod(path, int(mode))
        except OSError:
            pass
    forget(fix_id)
    return _result(True, "Put back the previous file permissions.")


def apply_scheduler() -> dict:
    script = SUITE_DIR / "install_scheduler.sh"
    rc, out = _run([str(script), "--install"], timeout=60)
    if rc != 0 or timer_enabled() is not True:
        return _result(False, "Couldn't turn on the daily job: " + (out.strip().splitlines()[-1] if out.strip() else "unknown error"))
    remember("scheduler", {"installed": True})
    return _result(True, "Daily background protection is on.")


def apply_sensors_timer() -> dict:
    rc, out = _run([str(SUITE_DIR / "install_scheduler.sh"), "--install-sensors"], timeout=60)
    if rc != 0 or sensors_timer_enabled() is not True:
        return _result(False, "Couldn't turn on live monitoring: " + (out.strip().splitlines()[-1] if out.strip() else "unknown error"))
    _run([sys.executable, str(SUITE_DIR / "sensors.py"), "--run"], timeout=60)         # learn what's normal right away
    remember("sensors_timer", {"installed": True})
    return _result(True, "Live monitoring is on. It is learning what's normal on this laptop.")


def undo_sensors_timer() -> dict:
    rc, out = _run([str(SUITE_DIR / "install_scheduler.sh"), "--uninstall-sensors"], timeout=60)
    if rc != 0:
        return _result(False, "Couldn't turn off live monitoring.")
    forget("sensors_timer")
    return _result(True, "Live monitoring is off.")


def undo_scheduler() -> dict:
    rc, out = _run([str(SUITE_DIR / "install_scheduler.sh"), "--uninstall"], timeout=60)
    if rc != 0:
        return _result(False, "Couldn't remove the daily job.")
    forget("scheduler")
    return _result(True, "Daily background protection is off.")


USER_FIXES = {
    "scheduler": (apply_scheduler, undo_scheduler), "sensors_timer": (apply_sensors_timer, undo_sensors_timer),
    "vino_off": (apply_vino_off, undo_vino_off), "vino_prompt": (apply_vino_prompt, lambda: undo_gsettings("vino_prompt")),
    "vino_tailscale": (apply_vino_tailscale, lambda: _undo_tailscale()), "screen_lock": (apply_screen_lock, lambda: undo_gsettings("screen_lock")),
    "lock_notifications": (apply_lock_notifications, lambda: undo_gsettings("lock_notifications")),
    "perms_ssh": (apply_perms_ssh, lambda: undo_modes("perms_ssh")), "perms_secrets": (apply_perms_secrets, lambda: undo_modes("perms_secrets")),
}
ROOT_FIXES = ("sysctl", "ufw_ipv6", "ufw_logging")


def _undo_tailscale() -> dict:
    res = undo_gsettings("vino_tailscale")
    if res["ok"]:
        _kill_vino()
        _start_vino()
    return res


def apply(fix_id: str) -> dict:
    if fix_id in ROOT_FIXES:
        return _result(False, "This one needs your password: use the app, or run linux_hardening.sh --apply " + fix_id)
    if fix_id not in USER_FIXES:
        return _result(False, f"Unknown fix '{fix_id}'.")
    res = USER_FIXES[fix_id][0]()
    if res["ok"]:
        record_event("maintenance", "info", "hardening_applied", f"Hardening applied: {fix_id}")
    return res


def undo(fix_id: str) -> dict:
    if fix_id in USER_FIXES:
        res = USER_FIXES[fix_id][1]()
        if res["ok"]:
            record_event("maintenance", "info", "hardening_undone", f"Hardening undone: {fix_id}")
        return res
    return _result(False, "This one needs your password: run linux_hardening.sh --undo " + fix_id)


# ---- the root side's data: what to remember before, and what to hand back when undoing
def snapshot(fix_id: str) -> dict:
    if fix_id == "sysctl":
        return {"sysctl": {k: v for k in SYSCTL_TARGETS if (v := sysctl_value(k)) is not None}}
    if fix_id == "ufw_ipv6":
        return {"ipv6": "yes" if re.search(r"^IPV6=yes", read_text(Path(os.environ.get("LG_UFW_DEFAULT", "/etc/default/ufw"))) or "", re.M) else "no"}
    if fix_id == "ufw_logging":
        m = re.search(r"^LOGLEVEL=(\w+)", read_text(Path(os.environ.get("LG_UFW_CONF", "/etc/ufw/ufw.conf"))) or "", re.M)
        return {"loglevel": m.group(1) if m else "low"}
    return {}


def undo_args(fix_id: str) -> list[str]:
    """Validated words for the root undo script, taken from what was recorded when the fix was applied."""
    rec = load_undo().get(fix_id) or {}
    if fix_id == "sysctl":
        args = []
        for k, v in (rec.get("sysctl") or {}).items():
            if k in SYSCTL_TARGETS and isinstance(v, int) and 0 <= v <= 9:
                args += [k, str(v)]
        return args
    if fix_id == "ufw_logging":
        lvl = rec.get("loglevel")
        return [lvl] if lvl in ("off", "low", "medium", "high", "full") else []
    return []


def render_text(checks: list[dict]) -> str:
    sym = {"ok": "ok  ", "attention": "FIX ", "info": "info", "unknown": "?   "}
    lines = []
    for c in sorted(checks, key=lambda c: (STATE_ORDER[c["state"]], c["group"])):
        lines.append(f"[{sym[c['state']]}] {c['title']}: {c['summary']}")
        for f in c["fixes"]:
            lines.append(f"         fix: {f['label']}  ({f['id']}{', needs password' if f['kind'] == 'root' else ''})")
        if c["advice"] and c["state"] != "ok":
            lines.append(f"         -> {c['advice']}")
    s = score(checks)
    lines.append(f"\n{s['ok']} of {s['total']} in good shape ({s['percent']}%).")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--preview", metavar="FIX")
    g.add_argument("--apply", metavar="FIX")
    g.add_argument("--undo", metavar="FIX")
    g.add_argument("--snapshot", metavar="FIX")
    g.add_argument("--record", nargs=2, metavar=("FIX", "JSON"))
    g.add_argument("--undo-args", metavar="FIX")
    g.add_argument("--forget", metavar="FIX")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.check:
        cs = collect()
        print(json.dumps({"checks": cs, "score": score(cs), "applied": applied_fixes()}) if a.json else render_text(cs))
    elif a.preview:
        print("\n".join(preview(a.preview)))
    elif a.apply:
        r = apply(a.apply)
        print("\n".join(r["messages"]))
        return 0 if r["ok"] else 1
    elif a.undo:
        r = undo(a.undo)
        print("\n".join(r["messages"]))
        return 0 if r["ok"] else 1
    elif a.snapshot:
        print(json.dumps(snapshot(a.snapshot)))
    elif a.record:
        try:
            remember(a.record[0], json.loads(a.record[1]))
        except ValueError:
            return 1
    elif a.undo_args:
        words = undo_args(a.undo_args)
        if words:
            print("\n".join(words))
    elif a.forget:
        forget(a.forget)
    return 0


if __name__ == "__main__":
    sys.exit(main())

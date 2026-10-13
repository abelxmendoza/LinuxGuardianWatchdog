#!/usr/bin/env python3
"""Blue-team sensors: notice things that look like an attack while they are happening. (read-only, no root)

Each sensor watches one kind of evidence and turns *new* findings into events (see events.py) that the Timeline,
Incidents and notifications already understand. No AI here: every rule is plain, inspectable logic.

  auth       failed logins, a login right after failures, new accounts, sensitive sudo use   (/var/log/auth.log)
  processes  programs running from /tmp, whose file was deleted, or pretending to be kernel threads   (/proc)
  network    a program talking to the internet for the first time, on a suspicious port, or to a
             known-bad address from the free public blocklists (threat_intel.py)               (ss)
  autoruns   new startup entries, cron jobs, user services, shell start-up changes
  accounts   new users, uid 0 accounts, new members of the admin group           (/etc/passwd, /etc/group)
  usb        new USB devices, especially keyboard-like ones that also pretend to be storage
  commands   new programs dropped into ~/.local/bin and friends, or executables dropped in /tmp
  self       LinuxGuardian's own program files changing (hash baseline, judged against git)       (self_check.py)

A sensor only records what is NEW since it last ran; the first run just learns what is normal on this laptop, and
network behaviour is learned for three days before it alerts. Nothing here kills, blocks or changes anything.

  sensors.py --run [--json]       one pass of every sensor (what the timer runs)
  sensors.py --status [--json]    which sensors can work here, last run, learning state
  sensors.py --allow PATH         tell the sensors a program/folder is expected (a trailing / means a whole folder)

Test hooks: LG_HOME, LG_PROC, LG_AUTH_LOG, LG_SENSOR_HOME, LG_SENSOR_ETC, LG_PASSWD, LG_GROUP, LG_USB, LG_SENSOR_NOW.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

import self_check  # noqa: E402
import threat_intel  # noqa: E402
from events import lg_home, record_event  # noqa: E402

LEARN_SECONDS = 3 * 86400            # network behaviour is only learned, not alerted on, for this long after the first run
COOLDOWN = 24 * 3600                 # the same finding isn't announced again for this long
PRUNE_AFTER = 14 * 86400
FAILED_LOGIN_THRESHOLD = 5
TMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
SYSTEM_EXE_PREFIXES = ("/usr/", "/opt/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/snap/", "/app/")
INTERPRETERS = {"python", "python2", "python3", "node", "nodejs", "bash", "sh", "dash", "zsh", "perl", "ruby", "java", "php", "env", "deno", "bun"}
COMMON_PORTS = {80, 443, 53, 22, 123, 853, 8080, 8443, 993, 995, 587, 465, 143, 110, 5228, 5223, 3478, 19302, 5222, 4222}
SUSPICIOUS_PORTS = {4444: "Metasploit's default", 5555: "Android debug / common reverse shell", 1337: "classic 'hacker' port", 31337: "classic backdoor port",
                    6666: "IRC-style botnet port", 6667: "IRC (botnet command channel)", 6697: "IRC over TLS", 9001: "Tor relay", 9030: "Tor directory",
                    9050: "Tor SOCKS", 9150: "Tor Browser SOCKS", 12345: "classic backdoor port", 2323: "Telnet alternative (IoT botnets)"}
SENSITIVE_SUDO = re.compile(
    r"COMMAND=(?:/usr/bin/|/bin/)?(?:bash|sh|zsh|dash|su)(?:\s|$)|COMMAND=.*(?:/etc/sudoers|visudo|useradd|adduser|usermod|passwd|chmod\s+[ug]?\+s|chown\s+root|"
    r"curl[^|]*\|\s*(?:ba)?sh|wget[^|]*\|\s*(?:ba)?sh|nc\s+-e|ncat\s+-e|/dev/tcp/)", re.I)
NOISE_SUDO = re.compile(r"a password is required|conversation failed|could not identify password|COMMAND=(?:list|true)\b", re.I)


# =============================================================== plumbing
@dataclass
class Finding:
    key: str                       # stable identity: the same thing found again is not "new"
    severity: str                  # info | warning | critical
    event: str                     # machine name
    message: str                   # plain-language sentence
    entity: list[str] = field(default_factory=list)    # things incidents correlate on (exe path, user, remote address, file)
    technique: str = ""            # MITRE ATT&CK id, for naming and explaining
    stage: str = ""                # execution | persistence | privilege | credential | network | initial-access | discovery
    extra: dict = field(default_factory=dict)


def now() -> float:
    return float(os.environ.get("LG_SENSOR_NOW") or time.time())


def home() -> Path:
    return Path(os.environ.get("LG_SENSOR_HOME", str(Path.home())))


def etc() -> Path:
    return Path(os.environ.get("LG_SENSOR_ETC", "/etc"))


def state_path() -> Path:
    return lg_home() / "state" / "sensors.json"


def allow_path() -> Path:
    return lg_home() / "sensors_allow.json"


def load_state() -> dict:
    try:
        d = json.loads(state_path().read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict) -> None:
    p = state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state))
    tmp.replace(p)


def load_allow() -> dict:
    """User-maintained 'this is expected' list: {"exe": [paths or prefixes], "ports": [...]}"""
    try:
        d = json.loads(allow_path().read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def is_allowed(path: str, allow: dict) -> bool:
    return any(path == a or (a.endswith("/") and path.startswith(a)) for a in allow.get("exe", []))


def _run(cmd: list[str], timeout: float = 10) -> tuple[int, str]:
    env = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    return p.returncode, p.stdout


def redact_args(text: str) -> str:
    """Command lines often carry secrets. Never store them."""
    text = re.sub(r"(?i)(bearer\s+)\S+", r"\1[redacted]", text)
    text = re.sub(r"(?i)(--?(?:token|secret|password|passwd|pass|api[-_]?key|key|auth|authorization|bearer)[=\s]+)(?!\[redacted\])\S+", r"\1[redacted]", text)
    text = re.sub(r"(?i)((?:token|secret|password|passwd|api[-_]?key|authorization)\s*[=:]\s*)(?!bearer|\[redacted\])\S+", r"\1[redacted]", text)
    return re.sub(r"(://[^/\s:@]+:)[^@\s/]+@", r"\1[redacted]@", text)


@dataclass
class Ctx:
    state: dict
    now: float
    first_run: bool
    learning: bool                 # still learning what is normal (network rules stay quiet)
    allow: dict


# ============================================================== proc helper
def iter_processes():
    root = Path(os.environ.get("LG_PROC", "/proc"))
    try:
        entries = [p for p in root.iterdir() if p.name.isdigit()]
    except OSError:
        return
    for p in entries:
        try:
            exe = os.readlink(p / "exe")
        except OSError:
            exe = ""
        try:
            raw = (p / "cmdline").read_bytes()
        except OSError:
            raw = b""
        args = [a for a in raw.decode("utf-8", "replace").split("\0") if a]
        try:
            uid = p.stat().st_uid
        except OSError:
            uid = -1
        try:
            comm = (p / "comm").read_text().strip()
        except OSError:
            comm = ""
        yield {"pid": int(p.name), "uid": uid, "exe": exe, "args": args, "comm": comm}


def script_of(proc: dict) -> str:
    """For interpreter-run programs the interesting file is the script, not /usr/bin/python3."""
    exe_name = os.path.basename(proc["exe"].replace(" (deleted)", "")).rstrip("0123456789.")
    if exe_name in INTERPRETERS:
        for a in proc["args"][1:]:
            if not a.startswith("-") and ("/" in a or a.endswith((".py", ".js", ".sh", ".rb", ".pl"))):
                return a
    return ""


# ================================================================== sensors
def sensor_auth(ctx: Ctx) -> list[Finding]:
    path = Path(os.environ.get("LG_AUTH_LOG", "/var/log/auth.log"))
    st = ctx.state.setdefault("auth", {})
    try:
        info = path.stat()
        fh = path.open("r", errors="replace")
    except OSError as exc:
        raise SensorUnavailable(f"can't read {path} ({exc.strerror or exc}). Join the 'adm' group to let LinuxGuardian read login history.")
    with fh:
        if ctx.first_run or st.get("inode") != info.st_ino or info.st_size < st.get("offset", 0):
            # first look, or the log was rotated: start from where reading is meaningful
            start = info.st_size if ctx.first_run else 0
        else:
            start = st.get("offset", info.st_size)
        fh.seek(start)
        text = fh.read(2_000_000)
        st.update(inode=info.st_ino, offset=start + len(text.encode("utf-8", "replace")))
    out: list[Finding] = []
    fails: dict[str, list[str]] = defaultdict(list)
    accepted: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        if NOISE_SUDO.search(line) and "incorrect password" not in line:
            continue
        m = re.search(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)", line) or re.search(r"Invalid user (\S+) from (\S+)", line)
        if m:
            fails[m.group(2)].append(m.group(1))
            continue
        m = re.search(r"pam_unix\((?:sshd|login|gdm-password|su(?:-l)?|polkit-1):auth\): authentication failure;.*?(?:rhost=(\S*))?.*?\buser=(\S+)", line)
        if m:
            fails[m.group(1) or "this laptop"].append(m.group(2))
            continue
        m = re.search(r"sudo:\s+(\S+) : (\d+) incorrect password attempts?", line)
        if m:
            out.append(Finding(f"auth:sudo-fail:{m.group(1)}", "warning", "sudo_failed",
                               f"{m.group(1)} entered a wrong sudo password {m.group(2)} time(s).", [m.group(1)], "T1110", "credential", {"user": m.group(1)}))
            continue
        m = re.search(r"Accepted (\w+) for (\S+) from (\S+) port (\d+)", line)
        if m:
            accepted.append((m.group(2), m.group(3), m.group(1)))
            continue
        m = re.search(r"useradd\[\d+\]: new user: name=(\S+?),", line)
        if m:
            out.append(Finding(f"auth:new-user:{m.group(1)}", "warning", "new_user", f"A new user account '{m.group(1)}' was created.", [m.group(1)],
                               "T1136.001", "persistence", {"user": m.group(1)}))
            continue
        m = re.search(r"(?:gpasswd|usermod)\[\d+\]: .*?(?:add(?:ed)? )?(?:user )?'?(\S+?)'? (?:to|added to) (?:group )?'?(sudo|admin|wheel|docker|root)'?", line)
        if m:
            out.append(Finding(f"auth:group:{m.group(1)}:{m.group(2)}", "critical" if m.group(2) in ("sudo", "admin", "wheel", "root") else "warning",
                               "privilege_added", f"{m.group(1)} was added to the '{m.group(2)}' group.", [m.group(1)], "T1098", "privilege", {"user": m.group(1)}))
            continue
        if "sudo:" in line and "COMMAND=" in line and SENSITIVE_SUDO.search(line) and not NOISE_SUDO.search(line):
            m = re.search(r"sudo:\s+(\S+) : .*?COMMAND=(.*)$", line)
            if m:
                cmd = redact_args(m.group(2).strip())[:160]
                out.append(Finding(f"auth:sudo:{m.group(1)}:{hashlib.sha1(cmd.encode()).hexdigest()[:8]}", "info", "sudo_sensitive",
                                   f"{m.group(1)} ran a sensitive command with sudo: {cmd}", [m.group(1)], "T1548.003", "privilege", {"user": m.group(1)}))
    for src, users in fails.items():
        if len(users) >= FAILED_LOGIN_THRESHOLD:
            names = ", ".join(sorted(set(users))[:4])
            sev = "critical" if any(a[1] == src for a in accepted) else "warning"
            msg = f"{len(users)} failed login attempts from {src} (accounts tried: {names})."
            if sev == "critical":
                msg += " A login from the same place then SUCCEEDED."
            out.append(Finding(f"auth:brute:{src}", sev, "failed_logins", msg, [src], "T1110", "initial-access", {"remote": src, "count": len(users)}))
    for user, src, method in accepted:
        if src not in fails and src not in ("127.0.0.1", "::1"):
            seen = ctx.state.setdefault("auth", {}).setdefault("ssh_sources", [])
            if src not in seen:
                seen.append(src)
                if not ctx.first_run and not ctx.learning:
                    out.append(Finding(f"auth:ssh-new:{src}", "warning", "new_login_source", f"{user} logged in over SSH ({method}) from a new address, {src}.",
                                       [src, user], "T1021.004", "initial-access", {"remote": src, "user": user}))
    return out


def sensor_processes(ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    h = str(home())
    for p in iter_processes():
        exe = p["exe"]
        if not exe:
            if p["args"] and p["args"][0].startswith("[") and p["args"][0].endswith("]"):
                continue                                           # a real kernel thread: no exe, bracketed name
            continue
        deleted = exe.endswith(" (deleted)")
        path = exe.removesuffix(" (deleted)")
        if is_allowed(path, ctx.allow) or re.match(r"^/tmp/\.mount_\w+/", path):           # AppImage mounts are normal
            continue
        script = script_of(p)
        cmd = redact_args(" ".join(p["args"]))[:200]
        who = "root" if p["uid"] == 0 else "you" if p["uid"] == os.getuid() else f"user {p['uid']}"
        ent = [path] + ([script] if script else [])
        base = {"pid": p["pid"], "process": p["comm"] or os.path.basename(path), "exe": path, "cmd": cmd}
        in_tmp = path.startswith(TMP_DIRS) or path.startswith("memfd:") or exe.startswith("/memfd:")
        if in_tmp:
            sev = "critical" if p["uid"] == 0 else "warning"
            out.append(Finding(f"proc:tmp:{path}", sev, "proc_from_tmp",
                               f"A program is running from a temporary folder: {path} (as {who}). Legitimate software almost never does this; malware often does.",
                               ent, "T1036.005", "execution", base))
        elif deleted and not path.startswith(SYSTEM_EXE_PREFIXES):
            out.append(Finding(f"proc:deleted:{path}", "warning", "proc_deleted_exe",
                               f"A program is running although its file was deleted: {path} (as {who}). Malware does this to hide.",
                               ent, "T1070.004", "defense-evasion", base))
        if p["args"] and re.match(r"^\[[\w/:\-.]+\]$", p["args"][0]) and path and not path.startswith(("/usr/", "/bin/", "/sbin/")):
            out.append(Finding(f"proc:masq:{path}", "critical", "proc_masquerade",
                               f"A program pretends to be a kernel thread ('{p['args'][0]}') but is really {path}.", ent, "T1036.004", "defense-evasion", base))
    return out


def private_or_local(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return True
    return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a in ipaddress.ip_network("100.64.0.0/10")


def parse_ss(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 5:
            continue
        peer = cols[3]
        ip, _, port = peer.rpartition(":")
        m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        if not m or not port.isdigit():
            continue
        rows.append({"ip": ip.strip("[]"), "port": int(port), "comm": m.group(1), "pid": int(m.group(2))})
    return rows


def sensor_network(ctx: Ctx) -> list[Finding]:
    rc, out_text = _run(["ss", "-H", "-tnp", "state", "established"])
    if rc != 0 and not out_text:
        raise SensorUnavailable("`ss` isn't available.")
    base = ctx.state.setdefault("network", {"programs": {}})
    programs: dict = base.setdefault("programs", {})
    findings: list[Finding] = []
    proc_exe = {p["pid"]: p for p in iter_processes()}
    intel = threat_intel.load()
    for row in parse_ss(out_text):
        if private_or_local(row["ip"]):
            continue
        proc = proc_exe.get(row["pid"], {"exe": "", "args": [], "comm": row["comm"], "uid": -1})
        exe = proc["exe"].removesuffix(" (deleted)") or row["comm"]
        ident = script_of(proc) or exe                      # judge a python script by the script, not by python
        hit = intel.match(row["ip"]) if intel else []
        if hit:
            # Checked before the allow-list and during learning: a program being trusted doesn't make its server trustworthy.
            findings.append(Finding(f"ti:{row['ip']}:{ident}", "critical", "threat_intel_hit",
                                    f"{os.path.basename(ident) or row['comm']} is connected to {row['ip']}, an address on a public blocklist: "
                                    f"{threat_intel.describe_hit(hit)}.",
                                    [exe] + ([ident] if ident != exe else []) + [row["ip"]], "T1071", "network",
                                    {"pid": row["pid"], "process": row["comm"], "exe": exe, "remote": row["ip"], "port": row["port"],
                                     "protocol": "tcp", "lists": hit}))
        if is_allowed(exe, ctx.allow) or is_allowed(ident, ctx.allow):
            continue
        entry = programs.get(ident)
        port = row["port"]
        shown = os.path.basename(ident) or row["comm"]
        extra = {"pid": row["pid"], "process": row["comm"], "exe": exe, "remote": row["ip"], "port": port, "protocol": "tcp"}
        unusual_dir = exe.startswith(TMP_DIRS) or (str(home()) in exe and re.search(r"/\.[^/]+/", exe.replace(str(home()), "", 1)) is not None
                                                  and not re.search(r"/\.(?:cache|local|cargo|rustup|npm|nvm|config|vscode|var|pyenv|sdkman|gradle|m2|deno|bun|volta)/", exe))
        if entry is None:
            programs[ident] = {"first_seen": ctx.now, "ports": [port]}
            if not ctx.learning:
                sev = "warning" if unusual_dir else "info"
                note = " It runs from an unusual place." if unusual_dir else ""
                findings.append(Finding(f"net:new:{ident}", sev, "new_outbound_program",
                                        f"{shown} connected to the internet for the first time ({row['ip']}:{port}).{note}",
                                        [exe] + ([ident] if ident != exe else []) + [row["ip"]], "T1071", "network", extra))
        else:
            known_ports = entry.setdefault("ports", [])
            if port not in known_ports:
                known_ports.append(port)
                if not ctx.learning and port in SUSPICIOUS_PORTS:
                    findings.append(Finding(f"net:port:{ident}:{port}", "warning", "suspicious_port",
                                            f"{shown} connected to {row['ip']} on port {port}, a port known for {SUSPICIOUS_PORTS[port]}.",
                                            [exe, row["ip"]], "T1571", "network", extra))
                elif not ctx.learning and port not in COMMON_PORTS and port not in (ctx.allow.get("ports") or []):
                    findings.append(Finding(f"net:port:{ident}:{port}", "info", "unusual_port",
                                            f"{shown} connected to {row['ip']} on an unusual port ({port}) it hasn't used before.", [exe, row["ip"]],
                                            "T1571", "network", extra))
        if row["port"] in SUSPICIOUS_PORTS and entry is None and not ctx.learning:
            findings.append(Finding(f"net:port:{ident}:{port}", "warning", "suspicious_port",
                                    f"{shown} connected to {row['ip']} on port {port}, a port known for {SUSPICIOUS_PORTS[port]}.", [exe, row["ip"]],
                                    "T1571", "network", extra))
    return findings


def _digest(path: Path) -> str:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except OSError:
        return ""


def autorun_files() -> dict[str, str]:
    h, e = home(), etc()
    paths: list[Path] = []
    for d, pats in ((h / ".config/autostart", ("*.desktop",)), (h / ".config/systemd/user", ("*.service", "*.timer", "*.path")),
                    (h / ".config/environment.d", ("*.conf",)), (e / "cron.d", ("*",)), (e / "cron.hourly", ("*",)), (e / "cron.daily", ("*",)),
                    (e / "cron.weekly", ("*",)), (e / "systemd/system", ("*.service", "*.timer")), (e / "xdg/autostart", ("*.desktop",))):
        for pat in pats:
            try:
                paths += sorted(p for p in d.glob(pat) if p.is_file() and not p.is_symlink())
            except OSError:
                pass
    paths += [h / n for n in (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".xprofile")] + [e / "crontab", e / "ld.so.preload", e / "rc.local"]
    snap = {str(p): _digest(p) for p in paths if p.is_file()}
    rc, out = _run(["crontab", "-l"])
    if rc == 0 and out.strip():
        snap["crontab:user"] = hashlib.sha256(out.encode()).hexdigest()[:16]
    return snap


def package_owner(path: str) -> str:
    rc, out = _run(["dpkg", "-S", "--", path])
    if rc == 0 and ": " in out:
        return out.split(":")[0].strip()
    return ""


def sensor_autoruns(ctx: Ctx) -> list[Finding]:
    now_snap = autorun_files()
    old = ctx.state.get("autoruns")
    ctx.state["autoruns"] = now_snap
    if old is None:
        return []
    out = []
    for path, digest in now_snap.items():
        parent = Path(path).parent
        pname, gname = parent.name, parent.parent.name
        is_cron = pname.startswith("cron") or path == "crontab:user" or Path(path).name == "crontab"
        is_sd = (pname in ("user", "system") and gname == "systemd")
        is_auto = pname == "autostart"
        kind = "cron job" if is_cron else "systemd service" if is_sd else "autostart entry" if is_auto else "start-up file"
        tech = "T1053.003" if is_cron else "T1543.002" if is_sd else "T1547.013" if is_auto else "T1546.004"
        if path == str(etc() / "ld.so.preload"):
            tech, kind = "T1574.006", "library preload hook"
        if path not in old:
            owner = package_owner(path) if path.startswith(str(etc())) else ""
            if owner:
                out.append(Finding(f"auto:new:{path}", "info", "new_autostart", f"A new {kind} was installed by the package {owner}: {path}.", [path], tech, "persistence", {"path": path}))
            else:
                sev = "critical" if "ld.so.preload" in path else "warning"
                out.append(Finding(f"auto:new:{path}", sev, "new_autostart",
                                   f"A new {kind} appeared and no package owns it: {path}. Programs that want to survive a reboot add things like this.",
                                   [path], tech, "persistence", {"path": path}))
        elif old[path] != digest and digest:
            sev = "warning" if path.endswith((".bashrc", ".profile", ".zshrc", ".bash_profile", ".zprofile", ".xprofile")) or "ld.so" in path else "info"
            out.append(Finding(f"auto:mod:{path}:{digest}", sev, "autostart_changed", f"A {kind} was modified: {path}.", [path], tech, "persistence", {"path": path}))
    return out


def read_passwd() -> dict[str, tuple]:
    out = {}
    try:
        for line in Path(os.environ.get("LG_PASSWD", "/etc/passwd")).read_text().splitlines():
            f = line.split(":")
            if len(f) >= 7:
                out[f[0]] = (f[2], f[3], f[5], f[6])
    except OSError:
        pass
    return out


def read_group(name: str) -> list[str]:
    try:
        for line in Path(os.environ.get("LG_GROUP", "/etc/group")).read_text().splitlines():
            f = line.split(":")
            if f[0] == name and len(f) >= 4:
                return [m for m in f[3].split(",") if m]
    except OSError:
        pass
    return []


def sensor_accounts(ctx: Ctx) -> list[Finding]:
    users = read_passwd()
    admins = {g: read_group(g) for g in ("sudo", "admin", "wheel")}
    old = ctx.state.get("accounts")
    ctx.state["accounts"] = {"users": {k: list(v) for k, v in users.items()}, "admins": admins}
    if old is None:
        return []
    out = []
    for name, (uid, gid, hm, shell) in users.items():
        prev = old["users"].get(name)
        if prev is None:
            sev = "critical" if uid == "0" else "warning"
            msg = f"A new user account '{name}' exists" + (" with ROOT privileges (uid 0)." if uid == "0" else ".")
            out.append(Finding(f"acct:new:{name}", sev, "new_user", msg, [name], "T1136.001", "persistence", {"user": name}))
        elif prev[0] != uid and uid == "0":
            out.append(Finding(f"acct:uid0:{name}", "critical", "uid_zero", f"The account '{name}' now has root privileges (uid 0).", [name], "T1098", "privilege", {"user": name}))
        elif prev[3] != shell and shell.endswith(("sh", "zsh", "fish")) and not prev[3].endswith(("sh", "zsh", "fish")):
            out.append(Finding(f"acct:shell:{name}:{shell}", "warning", "shell_enabled", f"The system account '{name}' was given a login shell ({shell}).", [name], "T1098", "persistence", {"user": name}))
    for g, members in admins.items():
        for m in members:
            if m not in old.get("admins", {}).get(g, []):
                out.append(Finding(f"acct:admin:{m}:{g}", "critical", "privilege_added", f"{m} was added to the '{g}' (administrator) group.", [m], "T1098", "privilege", {"user": m}))
    return out


def usb_devices() -> dict[str, dict]:
    root = Path(os.environ.get("LG_USB", "/sys/bus/usb/devices"))
    devs: dict[str, dict] = {}
    try:
        entries = list(root.iterdir())
    except OSError:
        return devs

    def rd(p: Path) -> str:
        try:
            return p.read_text().strip()
        except OSError:
            return ""

    for d in entries:
        vid, pid = rd(d / "idVendor"), rd(d / "idProduct")
        if not vid or ":" in d.name:
            continue
        classes = set()
        try:
            for sub in d.iterdir():
                if ":" in sub.name:
                    c = rd(sub / "bInterfaceClass")
                    if c:
                        classes.add(c)
        except OSError:
            pass
        devs[f"{vid}:{pid}:{rd(d / 'serial')}"] = {"name": (rd(d / "manufacturer") + " " + rd(d / "product")).strip() or f"{vid}:{pid}", "classes": sorted(classes)}
    return devs


def sensor_usb(ctx: Ctx) -> list[Finding]:
    devs = usb_devices()
    old = ctx.state.get("usb")
    ctx.state["usb"] = devs
    if old is None:
        return []
    out = []
    for key, d in devs.items():
        if key in old:
            continue
        hid, storage = "03" in d["classes"], "08" in d["classes"]
        if hid and storage:
            out.append(Finding(f"usb:{key}", "warning", "new_usb_composite", f"A USB device that acts as BOTH a keyboard and a storage drive was plugged in: {d['name']}. "
                                                                         "That combination is how 'BadUSB' attack devices work.", [key], "T1200", "initial-access", {"device": d["name"]}))
        else:
            kind = "keyboard-like device" if hid else "storage device" if storage else "device"
            out.append(Finding(f"usb:{key}", "info", "new_usb", f"A new USB {kind} was plugged in: {d['name']}.", [key], "T1200", "initial-access", {"device": d["name"]}))
    return out


def _is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def sensor_commands(ctx: Ctx) -> list[Finding]:
    h = home()
    out = []
    last = ctx.state.get("commands_last", ctx.now)
    seen = set(ctx.state.get("commands_seen", []))
    cur: set[str] = set()
    for d in (h / ".local/bin", h / ".cargo/bin", h / "go/bin", h / ".npm-global/bin", h / "bin", Path("/usr/local/bin")):
        try:
            for p in d.iterdir():
                if p.is_file() or p.is_symlink():
                    cur.add(str(p))
        except OSError:
            continue
    ctx.state["commands_seen"] = sorted(cur)[:5000]
    ctx.state["commands_last"] = ctx.now
    if not ctx.first_run:
        for path in sorted(cur - seen):
            if is_allowed(path, ctx.allow):
                continue
            where = "outside the package manager (pip, npm, cargo, a download)"
            out.append(Finding(f"cmd:new:{path}", "info", "new_local_command", f"A new command-line program appeared {where}: {path}.", [path], "T1195", "execution", {"path": path}))
    # Executables dropped into world-writable scratch folders since the last pass.
    for d in TMP_DIRS:
        try:
            for dirpath, dirnames, filenames in os.walk(d):
                depth = dirpath[len(d):].count("/")
                dirnames[:] = [x for x in dirnames if not x.startswith(".mount_")] if depth < 2 else []
                for fn in filenames[:300]:
                    p = Path(dirpath) / fn
                    try:
                        st = p.lstat()
                    except OSError:
                        continue
                    if st.st_mtime >= last and (st.st_mode & 0o111) and not ctx.first_run and not is_allowed(str(p), ctx.allow) and _is_elf(p):
                        out.append(Finding(f"cmd:tmp:{p}", "warning", "exe_dropped_in_tmp",
                                           f"A program file was created in a temporary folder: {p}. Downloaders and exploits often stage payloads there.",
                                           [str(p)], "T1105", "execution", {"path": str(p), "sha256": _digest(p)}))
        except OSError:
            continue
    return out


class SensorUnavailable(Exception):
    pass


def sensor_self(ctx: Ctx) -> list[Finding]:
    """The app watching itself: a changed or unexpected program file is reported like any other persistence attempt."""
    out = []
    for c in self_check.sensor_findings():
        key = "self:app:" + hashlib.sha1("|".join(c["paths"]).encode()).hexdigest()[:12]
        root = self_check.app_root()
        out.append(Finding(key, c["level"], "app_tampered" if c["level"] == "critical" else "app_modified", c["text"],
                           [str(root / p) for p in c["paths"][:6]], "T1554", "persistence", {"files": c["paths"][:20]}))
    return out


SENSORS = {"auth": sensor_auth, "processes": sensor_processes, "network": sensor_network, "autoruns": sensor_autoruns,
           "accounts": sensor_accounts, "usb": sensor_usb, "commands": sensor_commands, "self": sensor_self}
DESCRIPTIONS = {
    "auth": "Login history: failed logins, new accounts, sensitive sudo use",
    "processes": "Running programs: from /tmp, deleted, or pretending to be the kernel",
    "network": "Programs talking to the internet for the first time, or on suspicious ports",
    "autoruns": "Startup entries, cron jobs, services and shell start-up files",
    "accounts": "User accounts and who has administrator rights",
    "usb": "New USB devices (keyboard-like devices that also act as storage)",
    "commands": "New command-line programs and executables dropped in /tmp",
    "self": "LinuxGuardian's own files: changed, added or opened up to other users",
}


# ================================================================= engine
def run_once() -> dict:
    t = now()
    state = load_state()
    first_run = "first_run" not in state
    state.setdefault("first_run", t)
    learning = (t - state["first_run"]) < LEARN_SECONDS
    ctx = Ctx(state, t, first_run, learning, load_allow())
    threat_intel.refresh_if_due()                  # no-op unless the person turned known-bad address checking on
    seen: dict = state.setdefault("seen", {})
    report = {"time": t, "first_run": first_run, "learning": learning, "sensors": {}, "recorded": 0}
    for name, fn in SENSORS.items():
        info = {"ok": True, "findings": 0, "error": ""}
        try:
            found = fn(ctx)
        except SensorUnavailable as exc:
            info.update(ok=False, error=str(exc))
            found = []
        except Exception as exc:  # noqa: BLE001 - one broken sensor must never silence the others
            info.update(ok=False, error=f"{type(exc).__name__}: {exc}")
            found = []
        for f in found:
            info["findings"] += 1
            if t - seen.get(f.key, 0) < COOLDOWN:
                continue
            seen[f.key] = t
            extra = dict(f.extra)
            extra.update(entity=f.entity, technique=f.technique, stage=f.stage, key=f.key, sensor=name)
            record_event("sensor", f.severity, f.event, f.message, **extra)
            report["recorded"] += 1
        report["sensors"][name] = info
    for k in [k for k, v in seen.items() if t - v > PRUNE_AFTER]:
        del seen[k]
    if t - state.get("last_maintain", 0) > 86400:
        try:
            self_check.maintain()                          # snapshot state files, rotate the log, prune old snapshots
        except Exception:  # noqa: BLE001 - upkeep must never silence the sensors
            pass
        state["last_maintain"] = t
    state["last_run"] = t
    state["last_report"] = {k: v for k, v in report.items() if k != "sensors"} | {"sensors": {n: {"ok": i["ok"], "error": i["error"]} for n, i in report["sensors"].items()}}
    save_state(state)
    return report


def status() -> dict:
    state = load_state()
    t = now()
    fr = state.get("first_run")
    last = state.get("last_report", {}).get("sensors", {})
    return {
        "active": bool(state.get("last_run")), "timer": timer_enabled(), "first_run": fr, "last_run": state.get("last_run"),
        "learning_until": (fr + LEARN_SECONDS) if fr else None, "learning": bool(fr and (t - fr) < LEARN_SECONDS),
        "threat_intel": threat_intel.status(),
        "sensors": [{"name": n, "description": DESCRIPTIONS[n], "ok": last.get(n, {}).get("ok", None), "error": last.get(n, {}).get("error", "")} for n in SENSORS],
    }


def allow_path_entry(path: str) -> bool:
    """Add one 'this is expected' path (absolute, no wildcards). Returns False if it isn't acceptable."""
    if not path.startswith("/") or any(c in path for c in "*?\n\0") or path in ("/", "/tmp/", "/tmp", "/usr/", "/home/", "/var/", "/etc/"):
        return False
    data = load_allow()
    exes = data.setdefault("exe", [])
    if path not in exes:
        exes.append(path)
    p = allow_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.replace(p)
    return True


def timer_enabled() -> bool | None:
    if not shutil.which("systemctl"):
        return None
    rc, out = _run(["systemctl", "--user", "is-enabled", "linuxguardian-sensors.timer"])
    return out.strip() == "enabled"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--run", action="store_true")
    g.add_argument("--status", action="store_true")
    g.add_argument("--allow", metavar="PATH")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.allow:
        if allow_path_entry(a.allow):
            print(f"OK: '{a.allow}' is now treated as expected.")
            return 0
        print("Refused: give a specific absolute path (not a broad folder like /tmp/).", file=sys.stderr)
        return 1
    if a.run:
        r = run_once()
        if a.json:
            print(json.dumps(r))
        else:
            bad = {n: i["error"] for n, i in r["sensors"].items() if not i["ok"]}
            print(f"Sensors ran: {len(r['sensors']) - len(bad)} of {len(r['sensors'])} working, {r['recorded']} new finding(s)"
                  + (" (first run: learned what's normal)" if r["first_run"] else "") + ".")
            for n, e in bad.items():
                print(f"  {n}: {e}")
    else:
        s = status()
        print(json.dumps(s) if a.json else "\n".join(f"{'ok ' if x['ok'] else 'OFF' if x['ok'] is False else '?  '} {x['name']}: {x['description']}" + (f"  [{x['error']}]" if x["error"] else "") for x in s["sensors"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())

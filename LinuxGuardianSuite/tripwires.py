#!/usr/bin/env python3
"""Tripwires: the handful of settings an attacker changes to keep access or to poison what you install.  (read-only, no root)

Most intrusions don't stop at running something once. They add a way back in, give themselves more rights, loosen a login rule,
or redirect where your tools download code from. Each of those is a change to one small, rarely edited file, so each is
watched, and a change is reported within minutes:

  ssh keys        a new key in ~/.ssh/authorized_keys is a permanent door                                  critical
  sudo rules      /etc/sudoers and /etc/sudoers.d (root-only files: judged by their size and timestamp)    warning
  ssh settings    sshd_config: empty passwords, root login, password login, a different key file            critical/warning
  ssh client      ~/.ssh/config running a command (ProxyCommand, LocalCommand, Match exec)                  warning
  login rules     /etc/pam.d: a rule that lets anyone in, or runs a program at login                       critical/warning
  polkit          the rules that decide what asks for a password                                            warning
  /etc/hosts      a name quietly pointed at another address                                                 warning
  kernel modules  modules loaded at boot (a rootkit's way in)                                               warning
  login environment  /etc/profile.d, /etc/environment, library search paths                                 warning
  apt             new software sources and keys, and hooks that run commands during updates                 warning/critical
  pip/npm/cargo/git  a different package index or registry, a git alias or hook that runs commands          warning

The first look only records what is normal. After that a change is reported once. A file a package installed is reported as
information, not an alert. Nothing is blocked or reverted: this is a smoke detector.

  tripwires.py --check [--json]    what changed since the last look (also what the live monitor runs)
  tripwires.py --list              what is being watched

Test hooks: LG_HOME, LG_SENSOR_HOME, LG_SENSOR_ETC.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

MAX_READ = 512 * 1024
SEV_RANK = {"info": 0, "warning": 1, "critical": 2}
KEY_TYPES = re.compile(r"^(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-\S+|sk-\S+)$")

# group id -> title, ATT&CK technique, what a change means, how a plain change is rated, whether the file is root-only (stat only)
GROUPS = {
    "sudoers": ("sudo rules", "T1548.003", "Someone may have given an account administrator rights without a password prompt.", "warning", True),
    "polkit": ("administrator-prompt (polkit) rules", "T1548", "These rules decide what is allowed without asking for a password.", "warning", True),
    "pam": ("login rules (PAM)", "T1556.003", "A login rule can be changed to accept anyone or to run a program when someone logs in.", "info", False),
    "sshd": ("SSH server settings", "T1021.004", "These settings decide who may log in over the network, and how.", "info", False),
    "ssh_client": ("SSH client settings", "T1572", "A client setting can run a command every time you connect somewhere.", "info", False),
    "hosts": ("/etc/hosts", "T1565.001", "Names listed here override DNS: a bank or a download site can be pointed at another machine.", "warning", False),
    "kernel_modules": ("kernel modules loaded at boot", "T1547.006", "A module loaded at boot runs inside the kernel: the usual home of a rootkit.", "warning", False),
    "login_env": ("login environment", "T1546.004", "These files run for every login or decide which libraries programs load.", "warning", False),
    "apt": ("software sources (apt)", "T1195", "Software sources and keys decide what the system trusts when it installs and updates programs.", "warning", False),
    "tool_config": ("pip / npm / cargo / git settings", "T1195.002", "These settings decide where your developer tools download code from.", "info", False),
}


def home() -> Path:
    return Path(os.environ.get("LG_SENSOR_HOME", str(Path.home())))


def etc() -> Path:
    return Path(os.environ.get("LG_SENSOR_ETC", "/etc"))


def package_owner(path: str) -> str:
    """The installed package that owns this file, or '' (the same question the other sensors ask)."""
    try:
        r = subprocess.run(["dpkg", "-S", "--", path], capture_output=True, text=True, timeout=10, check=False, env=dict(os.environ, LC_ALL="C"))
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return r.stdout.split(":")[0].strip() if r.returncode == 0 and ": " in r.stdout else ""


def watches() -> dict[str, list[Path]]:
    h, e = home(), etc()

    def g(base: Path, pattern: str) -> list[Path]:
        try:
            return sorted(p for p in base.glob(pattern) if p.is_file() and not p.is_symlink())
        except OSError:
            return []

    return {
        "sudoers": [e / "sudoers"] + g(e / "sudoers.d", "*"),
        "polkit": g(e / "polkit-1/rules.d", "*") + g(e / "polkit-1/localauthority", "**/*"),
        "pam": g(e / "pam.d", "*"),
        "sshd": [e / "ssh/sshd_config"] + g(e / "ssh/sshd_config.d", "*"),
        "ssh_client": [h / ".ssh/config"],
        "hosts": [e / "hosts"],
        "kernel_modules": [e / "modules"] + g(e / "modules-load.d", "*") + g(e / "modprobe.d", "*"),
        "login_env": g(e / "profile.d", "*") + [e / "environment", e / "ld.so.conf"] + g(e / "ld.so.conf.d", "*"),
        "apt": [e / "apt/sources.list"] + g(e / "apt/sources.list.d", "*") + g(e / "apt/trusted.gpg.d", "*") + g(e / "apt/keyrings", "*")
               + g(e / "apt/apt.conf.d", "*") + g(e / "apt/preferences.d", "*"),
        "tool_config": [h / ".config/pip/pip.conf", h / ".pip/pip.conf", e / "pip.conf", h / ".npmrc", h / ".yarnrc", h / ".condarc",
                        h / ".cargo/config.toml", h / ".cargo/config", h / ".gitconfig", h / ".config/git/config"],
    }


# ============================================================ parsing
def _clean(text: str, limit: int = 80) -> str:
    return "".join(c if c.isprintable() else "?" for c in text)[:limit]


def parse_authorized_keys(text: str) -> dict[str, str]:
    """fingerprint -> readable label. Only a hash of each key is kept."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        toks = line.split()
        for i, tok in enumerate(toks):
            if KEY_TYPES.match(tok) and i + 1 < len(toks):
                fp = hashlib.sha256(toks[i + 1].encode()).hexdigest()[:16]
                comment = _clean(" ".join(toks[i + 2:]), 40)
                forced = " (forced command)" if i > 0 and "command=" in " ".join(toks[:i]) else ""
                out[fp] = f"{tok} {comment}".strip() + forced
                break
    return out


def risks_sshd(text: str) -> list[str]:
    out = []
    for raw in text.splitlines():
        parts = raw.split("#", 1)[0].split()
        if len(parts) < 2:
            continue
        k, v = parts[0].lower(), parts[1].lower()
        if k == "permitemptypasswords" and v == "yes":
            out.append("critical|the SSH server accepts empty passwords")
        elif k == "permitrootlogin" and v == "yes":
            out.append("critical|the SSH server lets root log in with a password")
        elif k == "passwordauthentication" and v == "yes":
            out.append("warning|the SSH server accepts passwords (keys only is safer)")
        elif k == "authorizedkeysfile" and any(not x.startswith((".ssh/", "%h/.ssh/", "/etc/ssh/")) for x in parts[1:]):
            out.append("warning|the SSH server reads login keys from an unusual place: " + _clean(" ".join(parts[1:]), 60))
        elif k == "gatewayports" and v in ("yes", "clientspecified"):
            out.append("warning|the SSH server lets tunnels listen on every network interface")
        elif k == "permituserenvironment" and v == "yes":
            out.append("warning|the SSH server lets users set their environment (a known way to run code at login)")
    return out


def risks_ssh_client(text: str) -> list[str]:
    out = []
    for raw in text.splitlines():
        parts = raw.split("#", 1)[0].strip().split(None, 1)
        if len(parts) < 2:
            continue
        k = parts[0].lower().rstrip("=")
        if k in ("proxycommand", "localcommand"):
            out.append(f"warning|your SSH client runs a command when you connect ({k}): " + _clean(parts[1], 70))
        elif k == "permitlocalcommand" and parts[1].lower().startswith("yes"):
            out.append("warning|your SSH client is allowed to run local commands")
        elif k == "match" and parts[1].lower().startswith("exec"):
            out.append("warning|your SSH client runs a command to decide its settings (Match exec)")
    return out


def risks_pam(text: str) -> list[str]:
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if re.match(r"^auth\s+(?:\[[^\]]*\]|sufficient|optional)\s+pam_permit\.so", line):
            out.append("critical|a login rule accepts everyone (pam_permit in the auth stack)")
        elif re.search(r"\bpam_exec\.so\b", line):
            out.append("warning|a login rule runs a program: " + _clean(line, 70))
        elif re.search(r"\bpam_(?:python|script)\.so\b", line):
            out.append("warning|a login rule runs a script: " + _clean(line, 70))
    return out


APT_HOOK = re.compile(r"(?:Pre|Post)-Invoke|Update-(?:Pre|Post)-Invoke|Pre-Install-Pkgs|Post-Invoke-Success|Archive-Hook", re.I)


def risks_apt_hook(text: str) -> list[str]:
    out = []
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if APT_HOOK.search(line):
            out.append("hook|" + _clean(line, 90))
    return out


def _host(url: str) -> str:
    m = re.search(r"(?:[a-z+]+://)?(?:[^/@\s]*@)?([A-Za-z0-9._-]+)", url.strip().strip("\"'"))
    return m.group(1).lower() if m else ""


KNOWN_INDEXES = {"pypi.org", "files.pythonhosted.org", "download.pytorch.org", "pypi.ngc.nvidia.com", "registry.npmjs.org", "registry.yarnpkg.com",
                 "index.crates.io", "crates.io", "github.com", "static.crates.io"}


def risks_tool(path: str, text: str) -> list[str]:
    name = os.path.basename(path)
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^(index-url|extra-index-url|find-links|trusted-host)\s*[=:]\s*(\S+)", line, re.I)
        if m:
            h = _host(m[2])
            if h and h not in KNOWN_INDEXES:
                out.append(f"warning|pip downloads packages from {h} ({m[1]})")
            continue
        m = re.match(r"^(?:@[\w-]+:)?registry\s*=\s*(\S+)", line, re.I)
        if m and name in (".npmrc", ".yarnrc"):
            h = _host(m[1])
            if h and h not in KNOWN_INDEXES:
                out.append(f"warning|npm/yarn downloads packages from {h}")
            continue
        if path.endswith((".cargo/config", ".cargo/config.toml")) and re.match(r"^(?:replace-with|registry|index)\s*=", line):
            h = _host(line.split("=", 1)[1])
            if h and h not in KNOWN_INDEXES:
                out.append(f"warning|cargo downloads crates from {h}")
            continue
        if path.endswith((".gitconfig", ".config/git/config")):
            if re.match(r"^(?:sshCommand|hooksPath|fsmonitor)\s*=", line, re.I):
                out.append(f"warning|git is set to run a program ({_clean(line.split('=')[0].strip(), 20)})")
            elif re.match(r"^[\w-]+\s*=\s*!", line):
                out.append("warning|a git alias or helper runs a shell command: " + _clean(line, 60))
            elif re.match(r"^insteadOf\s*=", line, re.I):
                out.append("warning|git quietly rewrites repository addresses: " + _clean(line, 70))
    return out


def risks_hosts(text: str) -> list[str]:
    out = []
    for raw in text.splitlines():
        parts = raw.split("#", 1)[0].split()
        if len(parts) < 2:
            continue
        ip, names = parts[0], parts[1:]
        if ip.startswith("127.") or ip in ("::1", "0.0.0.0", "fe00::0", "ff00::0", "ff02::1", "ff02::2", "ff02::3") or ip.startswith("ff"):
            continue
        out.append(f"warning|/etc/hosts sends {_clean(' '.join(names), 50)} to {_clean(ip, 40)}")
    return out


PARSERS = {"sshd": risks_sshd, "ssh_client": risks_ssh_client, "pam": risks_pam, "hosts": risks_hosts}


# ============================================================ snapshot
def _signature(path: Path, root_only: bool) -> tuple[str, str]:
    """(signature, text). Content hash when the file is readable, otherwise size and timestamp."""
    try:
        st = path.stat()
    except OSError:
        return "gone", ""
    if not root_only and os.access(path, os.R_OK):
        try:
            data = path.read_bytes()[:MAX_READ]
            return "sha:" + hashlib.sha256(data).hexdigest()[:20], data.decode("utf-8", "replace")
        except OSError:
            pass
    return f"stat:{st.st_mtime_ns}:{st.st_size}:{st.st_ino}:{st.st_mode & 0o7777:o}", ""


def snapshot() -> dict:
    snap: dict = {"files": {}, "ssh_keys": {}, "risk": {}}
    for gid, paths in watches().items():
        root_only = GROUPS[gid][4]
        for p in paths:
            if not p.exists():
                continue
            sig, text = _signature(p, root_only)
            snap["files"][str(p)] = {"group": gid, "sig": sig}
            risks: list[str] = []
            if text:
                if gid in PARSERS:
                    risks = PARSERS[gid](text)
                elif gid == "apt" and "apt.conf.d" in str(p):
                    risks = risks_apt_hook(text)
                elif gid == "tool_config":
                    risks = risks_tool(str(p), text)
            if risks:
                snap["risk"][str(p)] = risks
    h = home()
    for name in ("authorized_keys", "authorized_keys2"):
        p = h / ".ssh" / name
        try:
            snap["ssh_keys"].update(parse_authorized_keys(p.read_text(errors="replace")[:MAX_READ]))
        except OSError:
            pass
    return snap


# ================================================================= diff
def _finding(key: str, severity: str, event: str, message: str, entity: list[str], technique: str, extra: dict | None = None) -> dict:
    return {"key": key, "severity": severity, "event": event, "message": message, "entity": entity, "technique": technique, "stage": "persistence",
            "extra": extra or {}}


def diff(old: dict | None, new: dict) -> list[dict]:
    """What changed between two snapshots, as findings. The first snapshot (old is None) only learns."""
    if old is None:
        return []
    out: list[dict] = []
    for fp, label in new["ssh_keys"].items():
        if fp not in old.get("ssh_keys", {}):
            out.append(_finding(f"tw:sshkey:{fp}", "critical", "tripwire_ssh_key_added",
                                f"A new SSH key was added to your authorized_keys ({label}). Anyone holding the matching private key can log in as you, "
                                "with no password, until it is removed.", [str(home() / ".ssh/authorized_keys")], "T1098.004", {"fingerprint": fp}))
    old_files, old_risk = old.get("files", {}), old.get("risk", {})
    for path, info in new["files"].items():
        gid = info["group"]
        title, tech, why, base_sev, _ro = GROUPS[gid]
        before = old_files.get(path)
        new_risks = [r for r in new["risk"].get(path, []) if r not in old_risk.get(path, [])]
        for r in new_risks:
            sev, _, text = r.partition("|")
            if sev == "hook":
                owner = package_owner(path)
                if owner:
                    continue                                  # a package's own update hook
                out.append(_finding(f"tw:risk:{path}:{hashlib.sha1(r.encode()).hexdigest()[:10]}", "critical", "tripwire_risky_setting",
                                    f"An apt hook that runs a command was added in {path}: {text}. It runs with administrator rights every time you update.",
                                    [path], "T1546", {"group": gid}))
                continue
            out.append(_finding(f"tw:risk:{path}:{hashlib.sha1(r.encode()).hexdigest()[:10]}", sev, "tripwire_risky_setting",
                                f"{title}: {text} (in {path}). {why}", [path], tech, {"group": gid}))
        if new_risks:
            continue                                           # the specific finding says it better than 'file changed'
        if before is None:
            owner = package_owner(path) if path.startswith(str(etc())) else ""
            if owner:
                out.append(_finding(f"tw:new:{path}:{info['sig']}", "info", "tripwire_changed", f"A new {title} file was installed by the package {owner}: {path}.",
                                    [path], tech, {"group": gid, "package": owner}))
            elif gid != "tool_config":
                out.append(_finding(f"tw:new:{path}:{info['sig']}", base_sev if base_sev != "info" else "warning", "tripwire_changed",
                                    f"A new file appeared in your {title} and no package owns it: {path}. {why}", [path], tech, {"group": gid}))
        elif before["sig"] != info["sig"] and gid != "tool_config":
            owner = package_owner(path) if path.startswith(str(etc())) else ""
            sev = "info" if owner else base_sev
            out.append(_finding(f"tw:mod:{path}:{info['sig']}", sev, "tripwire_changed",
                                f"Your {title} changed: {path}" + (f" (owned by the package {owner}, so probably an update)" if owner else "") + f". {why}",
                                [path], tech, {"group": gid, "package": owner}))
    return out


def run(state: dict) -> list[dict]:
    """One look, comparing with (and updating) `state['tripwires']`."""
    snap = snapshot()
    findings = diff(state.get("tripwires"), snap)
    state["tripwires"] = snap
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--list", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.list:
        for gid, paths in watches().items():
            present = [p for p in paths if p.exists()]
            print(f"{GROUPS[gid][0]}: {len(present)} file(s) watched")
        return 0
    import sensors                                            # only the command line needs the shared state file

    state = sensors.load_state()
    first = "tripwires" not in state
    findings = run(state)
    sensors.save_state(state)
    if a.json:
        print(json.dumps({"first_look": first, "findings": findings}))
    elif first:
        print("First look: recorded what is normal. Changes from now on will be reported.")
    else:
        print("\n".join(f"[{f['severity']}] {f['message']}" for f in findings) or "Nothing changed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Is this install healthy? Which features work, and what is missing for the ones that don't.

Checks (read-only, no root) the tools LinuxGuardian relies on, the desktop services it needs for password
prompts, its own files and scheduled jobs, and that every script in this install parses. Results are grouped
by FEATURE ("Rootkit check: limited, needs rkhunter") so you can see what is affected, with the fix for each.

  diagnostics.py [--json|--text]

Test hooks: LG_HOME; tools are found on PATH.
"""
from __future__ import annotations

import argparse
import json
import os
import py_compile
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent

# tool -> (features that need it, how to get it, essential for those features?)
TOOLS: dict[str, tuple[tuple[str, ...], str, bool]] = {
    "clamscan": (("Malware scan",), "sudo apt install clamav", True),
    "freshclam": (("Virus definition updates",), "sudo apt install clamav", True),
    "rkhunter": (("Rootkit check",), "sudo apt install rkhunter", True),
    "pkexec": (("Rootkit check", "Updates", "Firewall helper", "Hardening fixes that need a password", "Virus definition updates"),
               "sudo apt install policykit-1", True),
    "ufw": (("Firewall helper", "Firewall hardening"), "sudo apt install ufw", True),
    "apt-get": (("Updates", "App transfer"), "(part of Ubuntu)", True),
    "dpkg-query": (("Updates", "App transfer"), "(part of Ubuntu)", True),
    "apt-mark": (("App transfer", "Update holds"), "(part of Ubuntu)", True),
    "gsettings": (("Screen lock and Screen Sharing fixes",), "sudo apt install libglib2.0-bin", True),
    "ss": (("Exposure scan", "Screen Sharing check"), "sudo apt install iproute2", True),
    "ip": (("Exposure scan", "VPN status"), "sudo apt install iproute2", True),
    "systemctl": (("Scheduled protection", "Service checks"), "(part of Ubuntu)", True),
    "notify-send": (("Notifications",), "sudo apt install libnotify-bin", False),
    "nmcli": (("VPN status (Proton)",), "sudo apt install network-manager", False),
    "resolvectl": (("VPN status (DNS leak check)", "DNS privacy check"), "(part of systemd-resolved)", False),
    "tailscale": (("VPN status (Tailscale)",), "https://tailscale.com/download", False),
    "snap": (("Snap updates", "App transfer (snaps)"), "(part of Ubuntu)", False),
    "lsblk": (("Disk encryption check",), "(part of util-linux)", False),
    "mokutil": (("Secure Boot check",), "sudo apt install mokutil", False),
    "stdbuf": (("Live scan progress",), "sudo apt install coreutils", False),
}

# feature -> tools it needs (all essential ones must be present for "ready")
FEATURES: dict[str, tuple[str, ...]] = {
    "Malware scan": ("clamscan",),
    "Virus definition updates": ("freshclam", "pkexec"),
    "Rootkit check": ("rkhunter", "pkexec"),
    "Software updates": ("apt-get", "dpkg-query", "pkexec"),
    "App transfer": ("apt-mark", "dpkg-query"),
    "Firewall helper": ("ufw", "pkexec"),
    "Hardening checklist": ("gsettings", "ss", "ip"),
    "Hardening fixes that need a password": ("pkexec",),
    "VPN status": ("ip",),
    "Notifications": ("notify-send",),
    "Scheduled protection": ("systemctl",),
}


def _run(cmd: list[str], timeout: float = 8) -> tuple[int, str]:
    env = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    return p.returncode, p.stdout + p.stderr


def lg_home() -> Path:
    return Path(os.environ.get("LG_HOME", str(Path.home() / ".linuxguardian")))


def tool_report() -> list[dict]:
    rows = []
    for name, (needed_for, hint, essential) in TOOLS.items():
        path = shutil.which(name)
        rows.append({"name": name, "found": bool(path), "path": path or "", "needed_for": list(needed_for), "hint": hint, "essential": essential})
    return rows


def env_check(cid: str, title: str, ok: bool | None, ok_text: str, bad_text: str, hint: str = "", essential: bool = False) -> dict:
    state = "unknown" if ok is None else ("ok" if ok else ("problem" if essential else "note"))
    return {"id": cid, "title": title, "state": state, "detail": ok_text if ok else bad_text, "hint": hint if not ok else ""}


def environment_report() -> list[dict]:
    out = []
    pk = shutil.which("pkexec")
    if pk:
        try:
            setuid = bool(os.stat(pk).st_mode & stat.S_ISUID)
        except OSError:
            setuid = None
        out.append(env_check("pkexec_suid", "Password prompts can elevate", setuid, "pkexec is set up correctly.",
                             "pkexec isn't set-uid root, so the password prompt can't grant root.", "Reinstall policykit-1.", True))
    rc, _ = _run(["pgrep", "-x", "gnome-shell"])
    rc2, _ = _run(["pgrep", "-f", "polkit.*authentication-agent"])
    agent = rc == 0 or rc2 == 0
    out.append(env_check("polkit_agent", "A password-prompt agent is running", agent if shutil.which("pgrep") else None,
                         "Your desktop can show password prompts.",
                         "No polkit agent was found. Actions that need a password (updates, rootkit check, firewall rules) will fail silently.",
                         "Log in to a normal desktop session (GNOME provides the agent itself).", True))
    rc, state = _run(["systemctl", "--user", "is-system-running"])
    running = state.strip() in ("running", "degraded")
    out.append(env_check("systemd_user", "Your user systemd session works", running if shutil.which("systemctl") else None,
                         "The user service manager is running.", f"The user service manager says '{state.strip() or 'unavailable'}'.",
                         "Scheduled scans use it; log out and back in.", False))
    home = lg_home()
    try:
        home.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=home, delete=True):
            pass
        writable = True
    except OSError:
        writable = False
    out.append(env_check("data_dir", "LinuxGuardian can save its data", writable, f"{home} is writable.", f"{home} isn't writable.",
                         f"chmod u+rwx {home}", True))
    try:
        free = shutil.disk_usage(home if home.exists() else home.parent).free
        out.append(env_check("disk_space", "Enough free disk space", free > 500 * 1024 * 1024, f"{free // (1024 ** 3)} GB free.",
                             f"Only {free // (1024 ** 2)} MB free: scans and logs may fail.", "Free some space (Cache Cleaner can help).", True))
    except OSError:
        pass
    rc, enabled = _run(["systemctl", "--user", "is-enabled", "linuxguardian-scan.timer"])
    out.append(env_check("scheduler", "Daily protection is scheduled", enabled.strip() == "enabled" if shutil.which("systemctl") else None,
                         "The daily scan timer is installed.", "No daily scheduled scan, so nothing runs unless you open the app.",
                         "Run: LinuxGuardianSuite/install_scheduler.sh --install", False))
    desktop = Path.home() / ".local/share/applications/linuxguardian-watchdog.desktop"
    out.append(env_check("launcher", "App launcher is installed", desktop.exists(), "The menu/dock launcher is installed.",
                         "No launcher entry for the app.", "Run: LinuxGuardianSuiteUI/install_desktop_entry.sh --install", False))
    return out


def scripts_report() -> dict:
    """Does every script in this install at least parse? Catches a half-updated or damaged install."""
    bad, checked = [], 0
    for p in sorted(SUITE_DIR.glob("*.sh")):
        checked += 1
        if subprocess.run(["bash", "-n", str(p)], capture_output=True).returncode != 0:
            bad.append(p.name)
        elif not os.access(p, os.X_OK):
            bad.append(p.name + " (not executable)")
    for p in sorted(SUITE_DIR.glob("*.py")):
        checked += 1
        try:
            with tempfile.TemporaryDirectory() as tmp:
                py_compile.compile(str(p), cfile=str(Path(tmp) / "x.pyc"), doraise=True)
        except py_compile.PyCompileError:
            bad.append(p.name)
    return {"checked": checked, "broken": bad}


def gtk_report() -> dict:
    rc, out = _run([sys.executable, "-c", "import gi; gi.require_version('Gtk','4.0'); gi.require_version('Adw','1'); from gi.repository import Adw; print(Adw.get_minor_version())"])
    return {"ok": rc == 0, "detail": "GTK 4 and libadwaita are available." if rc == 0 else "GTK 4 / libadwaita for Python is missing: sudo apt install python3-gi gir1.2-adw-1"}


def features_report(tools: list[dict]) -> list[dict]:
    have = {t["name"]: t for t in tools}
    out = []
    for feature, needs in FEATURES.items():
        missing = [n for n in needs if not have.get(n, {}).get("found")]
        essential_missing = [n for n in missing if TOOLS[n][2]]
        status = "ready" if not missing else ("unavailable" if essential_missing else "limited")
        out.append({"feature": feature, "status": status, "missing": missing, "hints": [TOOLS[n][1] for n in missing]})
    return out


def collect(include_scripts: bool = True) -> dict:
    tools = tool_report()
    env = environment_report()
    features = features_report(tools)
    # A feature that needs a password prompt isn't really ready if no agent can show one.
    agent_missing = any(e["id"] == "polkit_agent" and e["state"] == "problem" for e in env)
    for f in features:
        if agent_missing and "pkexec" in FEATURES[f["feature"]] and f["status"] == "ready":
            f["status"], f["missing"] = "limited", ["polkit agent"]
            f["hints"] = ["Log in to a normal desktop session so password prompts can appear."]
    result = {"tools": tools, "environment": env, "features": features, "gtk": gtk_report()}
    if include_scripts:
        result["scripts"] = scripts_report()
    problems = [e for e in env if e["state"] == "problem"] + [f for f in features if f["status"] != "ready"]
    result["healthy"] = not problems and not (result.get("scripts") or {}).get("broken") and result["gtk"]["ok"]
    return result


def render_text(r: dict) -> str:
    sym = {"ready": "ok  ", "limited": "WARN", "unavailable": "FAIL"}
    lines = ["Features:"]
    for f in r["features"]:
        extra = f"  (needs {', '.join(f['missing'])})" if f["missing"] else ""
        lines.append(f"  [{sym[f['status']]}] {f['feature']}{extra}")
        for h in f["hints"]:
            lines.append(f"         fix: {h}")
    lines.append("\nEnvironment:")
    for e in r["environment"]:
        lines.append(f"  [{ {'ok': 'ok  ', 'problem': 'FAIL', 'note': 'note', 'unknown': '?   '}[e['state']] }] {e['title']}: {e['detail']}" + (f" -> {e['hint']}" if e["hint"] else ""))
    s = r.get("scripts")
    if s:
        lines.append(f"\nInstall: {s['checked'] - len(s['broken'])} of {s['checked']} scripts are intact" + (f"; broken: {', '.join(s['broken'])}" if s["broken"] else "."))
    lines.append(f"GTK: {r['gtk']['detail']}")
    lines.append("\nOverall: " + ("healthy." if r["healthy"] else "needs attention (see FAIL/WARN above)."))
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--text", action="store_true")
    a = ap.parse_args()
    r = collect()
    print(json.dumps(r) if a.json else render_text(r))
    return 0 if r["healthy"] else 1


if __name__ == "__main__":
    sys.exit(main())

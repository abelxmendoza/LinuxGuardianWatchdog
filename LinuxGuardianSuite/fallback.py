#!/usr/bin/env python3
"""Terminal fallback: every feature as a command you can run yourself, in case the app misbehaves.

Each action has up to two commands:

  * the app's own command   the same script the buttons run (needs the suite folder to be intact)
  * the plain-tools command the underlying Linux tools directly (clamscan, ss, ufw, apt...), which keeps working
                            even if LinuxGuardian itself is broken or has been tampered with

The window shows them, copies them, and can open them in a terminal. What opens is ALWAYS text from the fixed list below:
the only things ever filled in are validated values (a process id, an incident id), shell-quoted. Nothing is typed in
from outside, so "open in terminal" can't be used to run anything that isn't on this list.

  fallback.py --list [--json]            every action
  fallback.py --show ID [--param V]      the commands for one action
  fallback.py --open ID [--param V]      open it in a terminal window (what the button does)

Test hooks: LG_TERMINAL (path of a terminal program to use instead of searching).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent

# Validators for the few values that can be filled in.
PARAMS = {
    "pid": re.compile(r"[1-9][0-9]{0,8}"),
    "id": re.compile(r"[0-9a-f]{6,32}"),
}

READ, CHANGE = "read", "change"


def _a(aid, group, title, what, app, plain=None, *, safety=READ, password=False, param=None, why_plain=""):
    # `password` says whether the APP's command asks for your password (through the system's login prompt); whether the plain
    # command needs sudo is read from its text.
    return {"id": aid, "group": group, "title": title, "what": what, "app": app, "plain": plain, "safety": safety,
            "password": password, "param": param, "why_plain": why_plain}


# `app` and `plain` are templates: {S} is the suite folder, {P} the validated parameter. Everything else is literal.
ACTIONS = [
    # ------------------------------------------------------------------ scanning
    _a("scan", "Scanning", "Scan for malware", "ClamAV scan of your home folder (quick).",
       "{S}/linux_guardian.sh --scan", "clamscan -r --infected --exclude-dir='^/home/[^/]+/.cache' ~"),
    _a("scan_rootkit", "Scanning", "Scan + rootkit check", "The same scan, plus rkhunter's rootkit check as administrator.",
       "{S}/linux_guardian.sh --scan --rootkit", "clamscan -r --infected ~ && sudo rkhunter --check --sk --nocolors", password=True),
    _a("health", "Scanning", "Can I trust a scan right now?", "How old the virus definitions are, and the state of the updater and rootkit baseline.",
       "{S}/linux_guardian.sh --health", "ls -l --time-style=long-iso /var/lib/clamav/ && systemctl status clamav-freshclam --no-pager"),
    _a("definitions", "Scanning", "Update virus definitions", "Downloads the newest ClamAV signatures.",
       "{S}/linux_guardian.sh --update", "sudo freshclam", safety=CHANGE, password=True),
    _a("integrity_check", "Scanning", "Check file integrity", "Compares your watched files with the saved baseline.",
       "{S}/linux_watchdog.sh --check", None),
    # ------------------------------------------------------------------- updates
    _a("updates_check", "Updates", "What updates are waiting?", "Lists pending apt and snap updates. Changes nothing.",
       "{S}/linux_updates.sh --check", "apt list --upgradable 2>/dev/null; snap refresh --list"),
    _a("updates_preview", "Updates", "Preview installing updates", "Shows what would be installed. Changes nothing.",
       "{S}/linux_updates.sh --apply --dry-run", "apt-get -s upgrade"),
    _a("updates_security", "Updates", "Install security updates only", "Installs only the security fixes.",
       "{S}/linux_updates.sh --apply --security-only", "sudo unattended-upgrade -v", safety=CHANGE, password=True,
       why_plain="Ubuntu's own tool for exactly this."),
    # ------------------------------------------------------------ network & exposure
    _a("exposure", "Network", "What is listening, and who can reach it?", "Open ports and the firewall's view. Read-only.",
       "{S}/linux_exposure.sh --check", "ss -tulpn; sudo ufw status verbose"),
    _a("connections", "Network", "Who is this laptop talking to?", "Established internet connections and the programs behind them.",
       None, "ss -tnp state established"),
    _a("vpn", "Network", "VPN status (Tailscale / Proton)", "Whether the VPNs are connected, and whether traffic leaks.",
       "{S}/vpn_status.py", "tailscale status; ip route show default; resolvectl status"),
    _a("firewall", "Network", "Firewall status", "Whether ufw is on and its rules.", None, "sudo ufw status verbose"),
    # ------------------------------------------------------------------- hardening
    _a("hardening", "Hardening", "Hardening checklist", "What is weak on this laptop, and why. Read-only.",
       "{S}/hardening.py --check", None),
    _a("audit", "Hardening", "Security audit and score", "A scored posture check. Read-only.",
       "{S}/linux_security_audit.sh", "sudo lynis audit system", why_plain="Lynis is an independent auditing tool: sudo apt install lynis"),
    _a("diagnostics", "Hardening", "Which features work here?", "Feature-by-feature readiness check.", "{S}/diagnostics.py", None),
    # ---------------------------------------------------------------------- watching
    _a("sensors", "Watching", "Look for attacks in progress", "One pass of every live sensor.", "{S}/sensors.py --run", None),
    _a("incidents", "Watching", "Open incidents", "Related events grouped into stories.", "{S}/incidents.py", None),
    _a("timeline", "Watching", "Security timeline", "Recent warnings and criticals.", "{S}/timeline.py --min-severity warning", None),
    _a("failed_logins", "Watching", "Recent failed logins", "Password-guessing attempts.", None,
       "sudo grep -E 'Failed password|authentication failure' /var/log/auth.log | tail -40"),
    _a("recent_logins", "Watching", "Who logged in recently?", "Login history.", None, "last -n 20"),
    _a("startup_entries", "Watching", "What starts automatically?", "Autostart entries, cron jobs and user services.", None,
       "ls -la ~/.config/autostart /etc/cron.d 2>/dev/null; crontab -l; systemctl --user list-unit-files --state=enabled"),
    _a("tripwires", "Watching", "Did a security-relevant setting change?", "SSH keys, sudo and login rules, software sources, package registries.",
       "{S}/tripwires.py --check", "cat ~/.ssh/authorized_keys; sudo ls -l /etc/sudoers.d; cat /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null"),
    _a("decoys", "Watching", "Decoy files: status", "Fake secrets planted for intruders, and whether read-detection works on this disk.",
       "{S}/decoys.py --status", "ls -l ~/.ssh/old_deploy_key ~/.aws/credentials.bak ~/.env.production.bak"),
    _a("coverage", "Watching", "What can LinuxGuardian notice?", "The attack coverage map: covered, partial, not covered.", "{S}/attack_coverage.py", None),
    _a("threat_update", "Watching", "Update known-bad address lists", "Downloads the free public blocklists.",
       "{S}/threat_intel.py --update", "curl -fsSL https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt | head", safety=CHANGE),
    _a("evidence", "Watching", "Collect evidence for an incident", "A read-only evidence bundle for one incident.",
       "{S}/evidence.py --incident {P}", None, param="id"),
    # ------------------------------------------------------------------- processes
    _a("processes", "Processes", "What is using the CPU?", "The busiest programs.", "{S}/linux_process_manager.sh --list",
       "ps aux --sort=-%cpu | head -20"),
    _a("stop_process", "Processes", "Stop one program (by process id)", "Asks the program to quit (SIGTERM).",
       "{S}/linux_process_manager.sh --kill {P}", "kill {P}", safety=CHANGE, param="pid"),
    _a("cache_preview", "Cleaning", "How much space can caches free?", "Previews cache cleanup. Changes nothing.",
       "{S}/linux_cache_cleanup.sh --scan", "du -sh ~/.cache ~/.local/share/Trash 2>/dev/null"),
    # --------------------------------------------------------------- the app itself
    _a("self_check", "This app", "Is LinuxGuardian itself healthy?", "Checks the app's own files, permissions, timers and state.",
       "{S}/self_check.py --check", None),
    _a("quarantine_list", "This app", "What is in quarantine?", "Files moved aside after a malware scan.", "{S}/quarantine.py --list", "ls -la ~/.linuxguardian/quarantine"),
    _a("quarantine_restore", "This app", "Put a quarantined file back", "Restores it to where it came from.",
       "{S}/quarantine.py --restore {P}", None, safety=CHANGE, param="id"),
    _a("git_check", "This app", "Has the app's code been modified?", "Compares the install with the published version.", None,
       "git -C {S}/.. status --short && git -C {S}/.. diff --stat", why_plain="Works only for a checkout from GitHub."),
]
BY_ID = {a["id"]: a for a in ACTIONS}


class FallbackError(Exception):
    pass


PLACEHOLDER = {"pid": "<process id>", "id": "<id>"}


def _fill(template: str | None, param: str | None, spec: str | None, placeholder: bool = False) -> str | None:
    if template is None:
        return None
    value = ""
    if "{P}" in template:
        if placeholder:
            value = PLACEHOLDER.get(spec or "", "")
        elif spec is None or param is None or not PARAMS[spec].fullmatch(str(param)):
            raise FallbackError("This needs a valid " + ("process id (a number)" if spec == "pid" else "id") + ".")
        else:
            value = shlex.quote(str(param))
    # The suite folder can contain spaces; quoted, it still joins with what follows ('/a b'/script.sh is one word).
    return template.replace("{S}", shlex.quote(str(SUITE_DIR))).replace("{P}", value)


def _describe(a: dict, param: str | None, placeholder: bool = False) -> dict:
    return {"id": a["id"], "title": a["title"], "what": a["what"], "group": a["group"], "safety": a["safety"], "password": a["password"],
            "plain_password": bool(a["plain"] and "sudo" in a["plain"]), "needs_param": a["param"],
            "app_command": _fill(a["app"], param, a["param"], placeholder), "plain_command": _fill(a["plain"], param, a["param"], placeholder),
            "why_plain": a["why_plain"]}


def commands(aid: str, param: str | None = None) -> dict:
    """The commands for one action, with the (validated) parameter filled in."""
    a = BY_ID.get(aid)
    if a is None:
        raise FallbackError("No such action.")
    return _describe(a, param)


def listing() -> list[dict]:
    """Every action, with <placeholders> where a value is needed (for display and copying as a template)."""
    return [_describe(a, None, placeholder=True) for a in ACTIONS]


# ============================================================== terminal
TERMINALS = [("gnome-terminal", ["--"]), ("x-terminal-emulator", ["-e"]), ("konsole", ["-e"]), ("xfce4-terminal", ["-x"]),
             ("kitty", []), ("alacritty", ["-e"]), ("xterm", ["-e"])]


def find_terminal() -> tuple[str, list[str]] | None:
    override = os.environ.get("LG_TERMINAL")
    if override:
        return (override, ["-e"]) if Path(override).is_file() else None
    for name, flag in TERMINALS:
        path = shutil.which(name)
        if path:
            return path, flag
    return None


def wrap(command: str) -> str:
    """What the terminal runs: the command, then a pause so the output can be read before the window closes."""
    return f'{command}; status=$?; echo; echo "Finished (exit code $status). Press Enter to close."; read -r _'


def open_in_terminal(aid: str, which: str = "app", param: str | None = None) -> tuple[bool, str]:
    """Open one fixed action in a terminal window. `which` is 'app' or 'plain'."""
    try:
        c = commands(aid, param)
    except FallbackError as exc:
        return False, str(exc)
    cmd = c["app_command"] if which == "app" else c["plain_command"]
    if not cmd:
        return False, "That action has no command of this kind."
    term = find_terminal()
    if term is None:
        return False, "No terminal program found. Copy the command and paste it into any terminal."
    prog, flag = term
    try:
        subprocess.Popen([prog, *flag, "bash", "-lc", wrap(cmd)], start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        return False, f"Couldn't open the terminal ({exc.strerror or exc})."
    return True, "Opened in a terminal window."


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true")
    g.add_argument("--show", metavar="ID")
    g.add_argument("--open", metavar="ID")
    ap.add_argument("--param")
    ap.add_argument("--plain", action="store_true", help="with --open: run the plain-tools command")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.list:
        rows = listing()
        if a.json:
            print(json.dumps(rows))
        else:
            for r in rows:
                print(f"{r['group']:<10} {r['id']:<20} {r['title']}")
        return 0
    try:
        if a.show:
            c = commands(a.show, a.param)
            print(json.dumps(c) if a.json else "\n".join(x for x in (c["title"], f"  app:   {c['app_command']}" if c["app_command"] else "",
                                                                   f"  plain: {c['plain_command']}" if c["plain_command"] else "") if x))
            return 0
        ok, msg = open_in_terminal(a.open, "plain" if a.plain else "app", a.param)
        print(msg, file=sys.stdout if ok else sys.stderr)
        return 0 if ok else 1
    except FallbackError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

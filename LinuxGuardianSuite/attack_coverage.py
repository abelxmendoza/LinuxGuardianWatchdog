#!/usr/bin/env python3
"""Attack coverage map: which common attack techniques LinuxGuardian can notice, partly notice, or can't.

No tool checks for "every possible attack", and one that claimed to would give false confidence, which is a security problem
by itself. This is the honest version: the common techniques (named with MITRE ATT&CK ids, the industry's shared vocabulary),
each marked

  covered   a live sensor or feature reliably notices this
  partial   it notices some forms, or only after the fact, or only if you turn something on (the gap is written down)
  none      nothing here would notice it (and what would help)

A "covered" entry is not allowed to be a wish: tests check that every sensor, file and technique id an entry points at really
exists in the code, so this map can't drift away from what the program does. Entries that need something switched on (live
monitoring, the blocklists, decoys) show "turned off" until it is.

  attack_coverage.py [--json] [--gaps]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
TACTICS = ["Initial access", "Execution", "Persistence", "Privilege escalation", "Defense evasion", "Credential access", "Lateral movement",
           "Command and control", "Exfiltration", "Impact"]


def E(tid, name, tactic, plain, status, by, *, code=(), features=(), needs=(), gap="", priority=2):
    return {"id": tid, "name": name, "tactic": tactic, "plain": plain, "status": status, "by": by, "code": list(code), "features": list(features),
            "needs": list(needs), "gap": gap, "priority": priority}


ENTRIES = [
    # ---------------------------------------------------------------------------------------- initial access
    E("T1110", "Guessing passwords", "Initial access", "Trying many passwords until one works.", "covered",
      "The login sensor counts failed logins and escalates when one succeeds afterwards.", code=["T1110"], needs=["timer"]),
    E("T1021.004", "Logging in over SSH with stolen access", "Initial access", "Using SSH with a stolen password or key.", "partial",
      "A login right after failures is flagged, and new keys and weakened SSH settings are caught. A quiet login with a valid stolen key looks normal.",
      code=["T1021.004"], needs=["timer"], gap="No unusual-time, unusual-place or unusual-source login detection."),
    E("T1133", "Remote services left open", "Initial access", "A service reachable from outside that shouldn't be.", "covered",
      "The Exposure tab lists everything listening and who can reach it; Hardening checks the firewall.", features=["exposure_inventory.py", "hardening.py"]),
    E("T1190", "Exploiting a program that faces the network", "Initial access", "A bug in something listening for connections.", "partial",
      "Exposure shows what is reachable and Updates keeps it patched. A live exploit attempt itself isn't detected.", features=["exposure_inventory.py", "linux_updates.sh"],
      gap="No network intrusion detection.", priority=2),
    E("T1200", "A malicious USB device", "Initial access", "A USB stick that pretends to be a keyboard (BadUSB).", "covered",
      "The USB sensor flags new devices and especially keyboard-plus-storage combinations.", code=["T1200"], needs=["timer"]),
    E("T1566", "Phishing and malicious downloads", "Initial access", "A booby-trapped attachment or link.", "partial",
      "The malware scan checks files, and downloaded programs that run from /tmp are caught. Links and mail content are not looked at.",
      features=["linux_guardian.sh", "quarantine.py"], gap="No browser, mail or link inspection.", priority=2),
    E("T1195", "Poisoned software supply chain", "Initial access", "A bad package, a hijacked registry or a rogue software source.", "partial",
      "New command-line programs, changed pip/npm/cargo/git settings, new apt sources and update hooks are caught. A malicious package from the real registry is not.",
      code=["T1195", "T1195.002"], needs=["timer"], gap="No check of what a package does when installed."),
    # --------------------------------------------------------------------------------------------- execution
    E("T1059", "Running commands and scripts", "Execution", "Shells and interpreters doing the attacker's bidding.", "partial",
      "Programs running from /tmp or whose file was deleted are flagged. What an ordinary shell runs is not logged.", code=["T1036.005"], needs=["timer"],
      gap="No command history auditing (auditd would be needed).", priority=3),
    E("T1204", "You running something harmful", "Execution", "A fake installer or trojaned tool you start yourself.", "partial",
      "Malware scan on demand, and the first network call of a new program is flagged.", features=["linux_guardian.sh"], code=["T1071"], needs=["timer"],
      gap="Nothing stops you running it."),
    E("T1105", "Tools dropped onto the machine", "Command and control", "An attacker downloads a program into /tmp or ~/.local/bin.", "covered",
      "New executables in /tmp and your personal bin folders are reported with a hash.", code=["T1105"], needs=["timer"]),
    # ------------------------------------------------------------------------------------------- persistence
    E("T1547.013", "Starting at login (autostart)", "Persistence", "A desktop startup entry.", "covered", "Startup entries are watched and compared with the packages that own them.",
      code=["T1547.013"], needs=["timer"]),
    E("T1053.003", "Cron jobs", "Persistence", "A scheduled job that brings the attacker back.", "covered", "Cron files and your crontab are watched.", code=["T1053.003"], needs=["timer"]),
    E("T1543.002", "Services", "Persistence", "A new systemd service or timer.", "covered", "User and system service files are watched.", code=["T1543.002"], needs=["timer"]),
    E("T1546.004", "Shell start-up files", "Persistence", "A line added to .bashrc or .profile.", "covered", "Shell start-up files are hashed and checked every few minutes.",
      code=["T1546.004"], needs=["timer"]),
    E("T1098.004", "A new SSH key", "Persistence", "A key added to authorized_keys: a permanent door.", "covered", "A tripwire reports any new key in minutes (critical).",
      code=["T1098.004"], needs=["timer"]),
    E("T1098", "Giving an account more rights", "Persistence", "Adding a user to the administrator group or making an account root.", "covered",
      "New administrators, uid-0 accounts and newly enabled login shells are reported.", code=["T1098"], needs=["timer"]),
    E("T1546", "Hooks that run during updates", "Persistence", "A command attached to apt that runs as root on every update.", "covered",
      "A non-package apt hook is critical; package-owned hooks are ignored.", code=["T1546"], needs=["timer"]),
    E("T1136.001", "A new account", "Persistence", "An extra user created for later.", "covered", "New accounts and new administrators are reported.", code=["T1136.001"], needs=["timer"]),
    E("T1574.006", "Hijacking program loading", "Persistence", "LD_PRELOAD or a library search path change.", "covered",
      "/etc/ld.so.preload and library path settings are watched.", code=["T1574.006"], needs=["timer"]),
    E("T1556.003", "Weakening the login rules", "Persistence", "Changing PAM so anyone gets in.", "covered", "A rule accepting everyone, or one running a program at login, is critical.",
      code=["T1556.003"], needs=["timer"]),
    E("T1547.006", "Kernel modules", "Persistence", "A module loaded at boot, the home of rootkits.", "partial",
      "New module-loading configuration is flagged. A module loaded by hand isn't listed or checked.", code=["T1547.006"], needs=["timer"],
      gap="No check of what is currently loaded (lsmod) against a known-good list.", priority=2),
    E("T1554", "Tampering with this app", "Persistence", "Changing LinuxGuardian itself to hide.", "covered",
      "Its own files are hash-checked against git; new files, writable files and foreign owners are critical.", code=["T1554"], needs=["timer"]),
    # ---------------------------------------------------------------------------------- privilege escalation
    E("T1548.003", "Sudo abuse", "Privilege escalation", "Giving yourself passwordless administrator rights.", "covered",
      "Sensitive sudo use and any change to the sudo rules are reported.", code=["T1548.003"], needs=["timer"]),
    E("T1548", "Weakening prompts for passwords", "Privilege escalation", "Changing polkit rules.", "covered", "polkit rule changes are reported.", code=["T1548"], needs=["timer"]),
    E("T1548.001", "Setuid programs", "Privilege escalation", "A program that always runs as root.", "covered",
      "Every setuid/setgid program is baselined; a new one is critical in /tmp, your home or under an unexpected owner, and a changed one is flagged (checked every six hours).",
      code=["T1548.001"], needs=["timer"]),
    E("T1068", "Exploiting a bug to become root", "Privilege escalation", "A kernel or program vulnerability.", "partial",
      "Updates shows pending security fixes and Hardening applies kernel hardening settings. The exploit itself isn't detected.",
      features=["linux_updates.sh", "hardening.py"], gap="No exploit detection."),
    # ---------------------------------------------------------------------------------------- defense evasion
    E("T1036.004", "Pretending to be the system", "Defense evasion", "A program named like a kernel thread.", "covered", "Fake kernel threads are flagged.", code=["T1036.004"], needs=["timer"]),
    E("T1070.004", "Deleting its own file", "Defense evasion", "Running from a file that was deleted.", "covered", "Running programs whose file was deleted are flagged (updates excepted).",
      code=["T1070.004"], needs=["timer"]),
    E("T1070.002", "Wiping logs", "Defense evasion", "Clearing the login and system logs.", "none", "A shrunken or emptied log isn't noticed.",
      gap="Watch /var/log/auth.log and the journal for truncation or rotation gaps.", priority=1),
    E("T1055", "Hiding inside another program", "Defense evasion", "Process injection.", "none", "Nothing inspects process memory.", gap="Needs kernel-level tooling (eBPF/auditd).", priority=3),
    E("T1562", "Switching off defenses", "Defense evasion", "Turning off the firewall or the virus updater.", "partial",
      "A firewall switched off or set to accept everything, a stopped firewall service, virus updater or AppArmor is reported within minutes; if live monitoring itself is "
      "switched off, the daily scan says so.", code=["T1562.004", "T1562.001"], features=["hardening.py", "self_check.py"], needs=["timer"],
      gap="Only those protections are watched, not rkhunter's schedule or the kernel's own settings.", priority=2),
    E("T1014", "Rootkits", "Defense evasion", "Software that hides itself and others.", "partial", "rkhunter runs on demand with a verified baseline; nothing runs continuously.",
      features=["linux_guardian.sh", "rkhunter_baseline.py"], gap="Not continuous."),
    # ------------------------------------------------------------------------------------ credential access
    E("T1552.001", "Stealing secrets from files", "Credential access", "Hunting for SSH keys, cloud keys and .env files.", "partial",
      "Planted decoy secrets raise a critical alert when read. Real files can't be watched for reads.", code=["T1552.001"], needs=["timer", "decoys"],
      gap="Only works if you plant the decoys, and only for programs that open them."),
    E("T1555", "Stealing saved passwords", "Credential access", "Reading browser or keyring password stores.", "none", "Nothing watches these.", gap="Hard without kernel auditing.", priority=3),
    E("T1056.001", "Keylogging", "Credential access", "Recording what you type.", "none", "Not detected.", gap="Hard without kernel auditing.", priority=3),
    E("T1003", "Dumping credentials", "Credential access", "Reading memory or shadow files.", "none", "Not detected.", gap="Needs auditd rules on /etc/shadow and process memory.", priority=2),
    # ---------------------------------------------------------------------------------------- command and control
    E("T1071", "Calling home", "Command and control", "A program talking to an attacker's server.", "partial",
      "A first-time internet connection by a program, and any connection to an address on the public blocklists (once turned on), are flagged. Traffic content isn't inspected.",
      code=["T1071"], features=["threat_intel.py"], needs=["timer", "threat_intel"], gap="No traffic inspection, and unlisted servers pass.", priority=2),
    E("T1571", "Unusual ports", "Command and control", "A reverse shell or botnet on a strange port.", "covered", "Known-bad ports and first use of an unusual port are flagged.", code=["T1571"], needs=["timer"]),
    E("T1572", "Tunnels", "Command and control", "SSH or other tunnels carrying traffic.", "partial", "An SSH client setting that runs commands, or a server allowing tunnels, is flagged. A tunnel run by hand isn't.",
      code=["T1572"], needs=["timer"], gap="No tunnel detection."),
    # ---------------------------------------------------------------------------------------------- exfiltration
    E("T1041", "Sending your data out", "Exfiltration", "Uploading files to an attacker.", "partial", "The program making the first connection is noticed; how much it sends isn't measured.",
      code=["T1071"], needs=["timer"], gap="No upload volume monitoring.", priority=2),
    E("T1005", "Collecting your files", "Exfiltration", "Reading and bundling documents.", "none", "Not detected.", gap="Hard without file-access auditing.", priority=3),
    # -------------------------------------------------------------------------------------------------- impact
    E("T1486", "Ransomware", "Impact", "Encrypting your files.", "partial", "The integrity check reports changed documents on its next run. There is no live mass-encryption alarm and no backup check.",
      features=["linux_watchdog.sh", "integrity.py"], gap="Add a burst-of-changes tripwire on Documents; check that a recent backup exists.", priority=1),
    E("T1496", "Cryptomining", "Impact", "Using your CPU/GPU for someone else.", "partial", "The Processes tab shows what is hungry, and malware scans know miner signatures. Nothing watches for sustained CPU/GPU use.",
      features=["linux_process_manager.sh", "linux_guardian.sh"], gap="Alert on sustained unexplained CPU/GPU load (careful: ROS and training legitimately use both).", priority=2),
    E("T1565.001", "Redirecting names", "Impact", "Editing /etc/hosts to send a site elsewhere.", "covered", "Changes to /etc/hosts, apart from loopback entries, are reported.", code=["T1565.001"], needs=["timer"]),
    E("T1489", "Stopping services", "Impact", "Killing security or backup services.", "partial", "The security services above are watched, and the monitoring timer by the daily scan.",
      code=["T1562.001"], needs=["timer"], gap="Backup and other services aren't watched.", priority=2),
    E("T1485", "Destroying data", "Impact", "Wiping files or disks.", "none", "Not detected.", gap="Backups are the real defense; add a backup-health check.", priority=2),
]
BY_ID = {e["id"]: e for e in ENTRIES}


def _needs_state() -> dict[str, bool | None]:
    """Which optional things are switched on right now. None means unknown."""
    out: dict[str, bool | None] = {"timer": None, "threat_intel": None, "decoys": None}
    try:
        import sensors

        out["timer"] = sensors.timer_enabled()
    except Exception:  # noqa: BLE001 - coverage reporting must not fail because one probe did
        pass
    try:
        import threat_intel

        out["threat_intel"] = bool(threat_intel.enabled())
    except Exception:  # noqa: BLE001
        pass
    try:
        import decoys

        out["decoys"] = bool(decoys.status()["planted"])
    except Exception:  # noqa: BLE001
        pass
    return out


NEED_TEXT = {"timer": "turn on live monitoring (Incidents tab)", "threat_intel": "download the free blocklists (Incidents tab)", "decoys": "plant the decoy files (Incidents tab)"}


def evaluate(state: dict | None = None) -> list[dict]:
    """Every entry with its current effective state: active, or off because something it needs is switched off."""
    state = _needs_state() if state is None else state
    out = []
    for e in ENTRIES:
        off = [n for n in e["needs"] if state.get(n) is False]
        out.append({**e, "off": off, "off_text": [NEED_TEXT[n] for n in off],
                    "effective": "none" if e["status"] == "none" else ("off" if off else e["status"])})
    return out


def summary(state: dict | None = None) -> dict:
    rows = evaluate(state)
    counts = {k: sum(1 for r in rows if r["effective"] == k) for k in ("covered", "partial", "off", "none")}
    gaps = sorted((r for r in rows if r["status"] in ("none", "partial") and r["gap"]), key=lambda r: (r["priority"], r["status"] != "none", r["id"]))
    return {"total": len(rows), "counts": counts, "rows": rows, "tactics": TACTICS,
            "next_gaps": [{"id": r["id"], "name": r["name"], "gap": r["gap"], "priority": r["priority"]} for r in gaps[:8]]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--gaps", action="store_true", help="only what to build next")
    a = ap.parse_args()
    s = summary()
    if a.json:
        print(json.dumps(s))
        return 0
    c = s["counts"]
    print(f"{s['total']} common techniques: {c['covered']} covered, {c['partial']} partly, {c['off']} turned off, {c['none']} not covered.\n")
    if a.gaps:
        for g in s["next_gaps"]:
            print(f"[{g['priority']}] {g['id']} {g['name']}: {g['gap']}")
        return 0
    for t in TACTICS:
        print(t)
        for r in (r for r in s["rows"] if r["tactic"] == t):
            mark = {"covered": "[x]", "partial": "[~]", "off": "[off]", "none": "[ ]"}[r["effective"]]
            print(f"  {mark:<5} {r['id']:<10} {r['name']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

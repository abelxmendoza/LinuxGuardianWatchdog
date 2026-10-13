#!/usr/bin/env python3
"""Did something switch off a defense?  (read-only, no root)

One of the first things an intruder does is turn off whatever might notice them. This watches the few protections whose
sudden absence is the signal, and says so within minutes:

  firewall      ufw switched off, or its default for incoming connections changed to "accept"        critical
  firewall      the ufw service stopped (it must stay stopped for two looks in a row: reboots)      critical
  virus updater the ClamAV definitions updater stopped                                               warning
  AppArmor      the service that confines programs stopped                                           warning

It only reports a protection that WAS on and then went off. One that was never on is the Hardening tab's business, not an
alarm. Nothing is turned back on for you: switching a firewall on is your call.

  defenses.py --check [--json]    what is on now, and what was switched off since last time

Test hooks: LG_HOME, LG_UFW_CONF, LG_UFW_DEFAULT; systemctl is found on PATH.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

CONFIRM_LOOKS = 2              # a service must be down this many looks in a row (a reboot or a restart is not an attack)

SERVICES = {
    "freshclam": ("clamav-freshclam", "The virus-definition updater stopped, so scans will use ever older signatures.", "T1562.001", "warning"),
    "apparmor": ("apparmor", "AppArmor, which confines programs to what they should do, stopped.", "T1562.001", "warning"),
}


def _read(path: str) -> str:
    try:
        return Path(path).read_text()
    except OSError:
        return ""


def unit_state(unit: str) -> bool | None:
    """True if the systemd unit is active, False if it is installed but not active, None if it doesn't exist or can't be asked."""
    if not shutil.which("systemctl"):
        return None
    try:
        out = subprocess.run(["systemctl", "show", "-p", "LoadState,ActiveState", unit], capture_output=True, text=True, timeout=10, check=False,
                             env=dict(os.environ, LC_ALL="C")).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    d = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    if d.get("LoadState") != "loaded":
        return None
    return d.get("ActiveState") == "active"


def observe() -> dict:
    """What is on right now. A value of None means 'not installed or unknown': never alarming."""
    conf = _read(os.environ.get("LG_UFW_CONF", "/etc/ufw/ufw.conf"))
    default = _read(os.environ.get("LG_UFW_DEFAULT", "/etc/default/ufw"))
    enabled = re.search(r"^ENABLED=(\w+)", conf, re.M)
    policy = re.search(r'^DEFAULT_INPUT_POLICY="?(\w+)"?', default, re.M)
    obs: dict = {"ufw_enabled": None if not enabled else enabled.group(1).lower() == "yes",
                 "ufw_active": unit_state("ufw"), "ufw_policy": policy.group(1).upper() if policy else None}
    for key, (unit, *_rest) in SERVICES.items():
        obs[key] = unit_state(unit)
    return obs


def _f(key: str, severity: str, event: str, message: str, technique: str, entity: list[str]) -> dict:
    return {"key": key, "severity": severity, "event": event, "message": message, "entity": entity, "technique": technique, "stage": "defense-evasion", "extra": {}}


SERVICE_FIELDS = {"ufw": ("ufw_active", "The firewall service (ufw) stopped. Its rules are no longer being enforced.", "T1562.004", "critical")}
for _key, (_unit, _text, _tech, _sev) in SERVICES.items():
    SERVICE_FIELDS[_key] = (_key, _text, _tech, _sev)


def run(state: dict) -> list[dict]:
    """One look, comparing with (and updating) `state['defenses']`. The first look only learns."""
    now = observe()
    block = state.get("defenses")
    first = block is None
    block = block or {"last": {}, "ever_up": {}, "down": {}}
    last, ever_up, down = block["last"], block["ever_up"], block["down"]
    out: list[dict] = []
    if not first:
        # configuration is acted on at once: a config file doesn't flap like a service does
        if last.get("ufw_enabled") is True and now.get("ufw_enabled") is False:
            out.append(_f("def:ufw:disabled", "critical", "defense_disabled", "The firewall (ufw) was switched off. Everything listening on this laptop is now "
                          "reachable from the network. If you didn't do this, treat it as a sign of intrusion.", "T1562.004", ["/etc/ufw/ufw.conf"]))
        if last.get("ufw_policy") in ("DROP", "REJECT") and now.get("ufw_policy") == "ACCEPT":
            out.append(_f("def:ufw:policy", "critical", "defense_disabled", "The firewall's default for incoming connections was changed to ACCEPT, which "
                          "lets everything in unless a rule says otherwise.", "T1562.004", ["/etc/default/ufw"]))
    for name, (field, text, tech, sev) in SERVICE_FIELDS.items():
        v = now.get(field)
        if v is True:
            ever_up[name], down[name] = True, 0
        elif v is False and ever_up.get(name):
            down[name] = down.get(name, 0) + 1                  # only a protection that WAS on can have been switched off
            if not first and down[name] == CONFIRM_LOOKS:        # exactly once per outage, and only if it stays down
                out.append(_f(f"def:svc:{name}", sev, "defense_disabled", text, tech, [name]))
    block["last"] = {k: v for k, v in now.items() if v is not None} | {k: last[k] for k in last if now.get(k) is None}
    state["defenses"] = block
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    import sensors

    state = sensors.load_state()
    findings = run(state)
    sensors.save_state(state)
    obs = observe()
    if a.json:
        print(json.dumps({"now": obs, "findings": findings}))
        return 0
    def word(v):
        return "unknown / not installed" if v is None else "on" if v else "off"
    print(f"Firewall: enabled in config {word(obs['ufw_enabled'])}, service {word(obs['ufw_active'])}, incoming default {obs['ufw_policy'] or 'unknown'}")
    print(f"Virus-definition updater: {word(obs['freshclam'])}\nAppArmor: {word(obs['apparmor'])}")
    for f in findings:
        print(f"[{f['severity']}] {f['message']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

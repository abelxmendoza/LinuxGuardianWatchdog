#!/usr/bin/env python3
"""ROS 2 / robotics firewall helper: work out the narrowest ufw rules a robot link needs.

A default-deny firewall blocks ROS 2's discovery, so a laptop and a robot stop seeing each other. The
usual "fix" (open the whole port range to everyone, or turn the firewall off) trades the problem for a
worse one. This computes the specific rules instead: only your robot's address, only the UDP ports for
YOUR ROS domain, only the extras you tick. Nothing here changes anything: `--plan` prints the rules and
what they mean, and `linux_ros_firewall.sh --apply` is a separate, confirmed step.

  ros_firewall.py --detect [--json]
  ros_firewall.py --plan --peer ADDR [--domain N] [--preset NAME]... [--json]
  ros_firewall.py --presets

Peers are single addresses or CIDR networks no wider than /16. Never "any", never 0.0.0.0/0.
Test hooks: LG_ROS_HOME (stands in for $HOME), LG_ROS_OPT (stands in for /opt/ros).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from pathlib import Path

PORT_BASE, DOMAIN_GAIN = 7400, 250
MAX_DOMAIN = 232                      # RTPS: ports above 65535 are impossible past this
MIN_PREFIX_V4, MIN_PREFIX_V6 = 16, 48

# name -> (protocol, port or "lo:hi", what it is for)
PRESETS: dict[str, tuple[str, str, str]] = {
    "mavlink": ("udp", "14540,14550", "PX4/MAVLink: offboard control (14540) and ground control (14550)"),
    "xrce": ("udp", "8888", "PX4 uXRCE-DDS agent (ROS 2 <-> PX4 bridge)"),
    "foxglove": ("tcp", "8765", "Foxglove Studio WebSocket bridge"),
    "rosbridge": ("tcp", "9090", "rosbridge WebSocket server"),
}
DDS_NOTE = ("DDS discovery uses UDP multicast; managed switches with IGMP snooping also need IGMP queries to get through. "
            "If discovery works for a few minutes and then stops, run: sudo ufw allow in proto igmp")


def home() -> Path:
    return Path(os.environ.get("LG_ROS_HOME", str(Path.home())))


def dds_range(domain: int) -> str:
    """The UDP port range RTPS uses for one ROS domain (discovery + data, multicast and unicast)."""
    if not 0 <= domain <= MAX_DOMAIN:
        raise ValueError(f"ROS domain must be 0-{MAX_DOMAIN}")
    base = PORT_BASE + DOMAIN_GAIN * domain
    return f"{base}:{min(base + DOMAIN_GAIN - 1, 65535)}"      # the very last domains run out of port space


def parse_peer(text: str) -> str:
    """A validated, normalized address or network. Raises ValueError with a plain reason."""
    text = text.strip()
    if not text or text.lower() in {"any", "anywhere", "*"}:
        raise ValueError("A specific robot address is required, not 'anywhere'.")
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ValueError(f"'{text}' isn't an IP address or network.") from exc
    min_prefix = MIN_PREFIX_V4 if net.version == 4 else MIN_PREFIX_V6
    if net.prefixlen < min_prefix:
        raise ValueError(f"{net} is far too wide (that's {net.num_addresses:,} addresses). Use your robot's address, or a network no larger than /{min_prefix}.")
    if net.is_multicast or net.is_unspecified or net.network_address.is_loopback:
        raise ValueError(f"{net} isn't a robot's address.")
    return str(net.network_address) if net.num_addresses == 1 else str(net)


def rules(peer: str, domain: int, presets: list[str]) -> list[dict]:
    peer = parse_peer(peer)
    out = [{"name": "dds", "proto": "udp", "ports": dds_range(domain), "peer": peer,
            "why": f"ROS 2 discovery and data for domain {domain}"}]
    for name in presets:
        if name not in PRESETS:
            raise ValueError(f"Unknown preset '{name}'.")
        proto, ports, why = PRESETS[name]
        out.append({"name": name, "proto": proto, "ports": ports, "peer": peer, "why": why})
    for r in out:
        r["comment"] = f"LinuxGuardian ROS {r['name']}"
        r["command"] = f"sudo ufw allow from {r['peer']} to any port {r['ports']} proto {r['proto']} comment '{r['comment']}'"
    return out


_EXPORT = re.compile(r"^\s*(?:export\s+)?(ROS_DOMAIN_ID|ROS_LOCALHOST_ONLY|RMW_IMPLEMENTATION)=[\"']?([A-Za-z0-9_]+)[\"']?\s*(?:#.*)?$")


def detect() -> dict:
    """What this machine already says about its ROS setup (read-only; env first, then shell start-up files)."""
    found: dict[str, list[str]] = {"ROS_DOMAIN_ID": [], "ROS_LOCALHOST_ONLY": [], "RMW_IMPLEMENTATION": []}
    for key in found:
        if os.environ.get(key):
            found[key].append(os.environ[key])
    for name in (".bashrc", ".profile", ".bash_profile", ".zshrc"):
        try:
            for line in (home() / name).read_text(errors="replace").splitlines():
                m = _EXPORT.match(line)
                if m and m.group(2) not in found[m.group(1)]:
                    found[m.group(1)].append(m.group(2))
        except OSError:
            continue
    opt = Path(os.environ.get("LG_ROS_OPT", "/opt/ros"))
    distros = sorted(p.name for p in opt.iterdir() if p.is_dir()) if opt.is_dir() else []
    domains = []
    for d in found["ROS_DOMAIN_ID"]:
        if d.isdigit() and 0 <= int(d) <= MAX_DOMAIN and int(d) not in domains:
            domains.append(int(d))
    localhost = any(v in ("1", "true", "True") for v in found["ROS_LOCALHOST_ONLY"])
    return {"distros": distros, "domains": domains or [0], "domain_declared": bool(domains),
            "localhost_only": localhost, "rmw": found["RMW_IMPLEMENTATION"], "ros_present": bool(distros),
            "note": ("ROS_LOCALHOST_ONLY=1 is set, so ROS 2 only talks to this laptop: no firewall rules are needed."
                     if localhost else
                     "ROS 2 will talk to other machines, so a default-deny firewall blocks discovery until specific rules are added.")}


def plan(peer: str, domain: int, presets: list[str]) -> dict:
    rs = rules(peer, domain, presets)
    return {"peer": rs[0]["peer"], "domain": domain, "rules": rs, "notes": [DDS_NOTE],
            "effect": (f"Allows ONLY {rs[0]['peer']} to reach this laptop on {len(rs)} port group(s). "
                       "Nothing else changes: the default policy stays deny, ufw is not enabled or disabled, no rule is removed.")}


def render_plan(p: dict) -> str:
    lines = [p["effect"], ""]
    for r in p["rules"]:
        lines.append(f"  {r['proto'].upper()} {r['ports']:>11}  from {r['peer']}   {r['why']}")
    lines += ["", "Commands (what 'Apply' runs, one rule each):"] + [f"  {r['command']}" for r in p["rules"]] + ["", p["notes"][0]]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--detect", action="store_true")
    g.add_argument("--plan", action="store_true")
    g.add_argument("--presets", action="store_true")
    ap.add_argument("--peer")
    ap.add_argument("--domain", type=int)
    ap.add_argument("--preset", action="append", default=[])
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.presets:
        for name, (proto, ports, why) in PRESETS.items():
            print(f"{name}\t{proto}\t{ports}\t{why}")
        return 0
    if a.detect:
        d = detect()
        print(json.dumps(d) if a.json else f"{d['note']}\nDomains: {d['domains']}  ROS: {', '.join(d['distros']) or 'not found'}")
        return 0
    if not a.peer:
        ap.error("--plan needs --peer")
    domain = a.domain if a.domain is not None else detect()["domains"][0]
    try:
        p = plan(a.peer, domain, a.preset)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(p) if a.json else render_plan(p))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Firewall control: the state of ufw in plain language, and the exact, validated commands to change it.

Nothing here changes anything and nothing here needs root. It reads what a normal user may read (ufw's own settings
files, the service state, the block log if you are in the 'adm' group), parses what root hands back (`ufw status
numbered`), and turns a request ("allow 22/tcp from 192.168.1.0/24") into the exact ufw words or a plain reason why
not. `linux_firewall.sh` is the only thing that acts, through one fixed root script, after you have seen the preview.

  firewall_control.py --status [--kind KIND] [--json]          on/off, defaults, logging, service health
  firewall_control.py --blocks [--limit N] [--json]            what the firewall blocked recently (from the ufw log)
  firewall_control.py --plan-add --action A --port P [--proto X] [--from ADDR] [--label TEXT] [--json]
  firewall_control.py --parse-rules [--json] < `ufw status numbered` output

Test hooks: LG_UFW_CONF, LG_UFW_DEFAULT, LG_UFW_LOG (stand-ins for /etc/ufw/ufw.conf, /etc/default/ufw, /var/log/ufw.log);
systemctl and journalctl are found on PATH.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

ACTIONS = ("allow", "deny", "reject", "limit")
PROTOS = ("tcp", "udp", "any")
LOG_LEVELS = ("off", "low", "medium", "high", "full")
INCOMING_POLICIES = ("deny", "reject")            # "allow everything in" is what turning the firewall off is for, said plainly
OUTGOING_POLICIES = ("allow", "deny")
LABEL_RE = re.compile(r"[A-Za-z0-9 ._-]{0,40}")
POLICY_WORDS = {"DROP": "deny", "REJECT": "reject", "ACCEPT": "allow"}

# Ports people usually mean, so the form can offer them by name.
PRESETS: dict[str, tuple[str, str]] = {
    "SSH": ("22", "tcp"),
    "HTTP": ("80", "tcp"),
    "HTTPS": ("443", "tcp"),
    "Samba (file sharing)": ("445", "tcp"),
    "KDE Connect / GSConnect": ("1714:1764", "tcp"),
    "mDNS (local discovery)": ("5353", "udp"),
}


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return None


def _setting(text: str | None, key: str) -> str | None:
    if text is None:
        return None
    m = re.search(rf'^\s*{key}\s*=\s*"?([A-Za-z0-9_-]+)"?', text, re.M)
    return m.group(1) if m else None


def _run(*cmd: str, timeout: float = 5.0) -> tuple[int, str]:
    if not shutil.which(cmd[0]):
        return 127, ""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""
    return p.returncode, p.stdout


def service_state(unit: str = "ufw") -> str:
    code, out = _run("systemctl", "is-active", unit)
    return out.strip() or ("unknown" if code == 127 else "inactive")


def service_failure(unit: str = "ufw") -> str | None:
    """The last error line the service wrote this boot, if the journal is readable (it is for the 'adm' group)."""
    code, out = _run("journalctl", "-u", unit, "-b", "--no-pager", "-q", "-o", "cat", "-n", "40")
    if code != 0:
        return None
    for line in reversed(out.splitlines()):
        if re.search(r"fail|error|problem", line, re.I) and not line.startswith(f"{unit}.service:") and "Failed to start" not in line:
            return line.strip()[:200]
    return None


def status(kind: str | None = None) -> dict:
    conf = _read(os.environ.get("LG_UFW_CONF", "/etc/ufw/ufw.conf"))
    default = _read(os.environ.get("LG_UFW_DEFAULT", "/etc/default/ufw"))
    installed = bool(shutil.which("ufw")) or conf is not None
    enabled = _setting(conf, "ENABLED")
    service = service_state("ufw") if installed else "missing"
    policies = {name: POLICY_WORDS.get((_setting(default, f"DEFAULT_{key}_POLICY") or "").upper())
                for name, key in (("incoming", "INPUT"), ("outgoing", "OUTPUT"), ("routed", "FORWARD"))}
    st = {
        "kind": kind or ("ufw" if service == "active" else "unknown"),
        "installed": installed,
        "enabled": None if enabled is None else enabled.lower() == "yes",
        "service": service,
        "logging": (_setting(conf, "LOGLEVEL") or "unknown").lower(),
        "ipv6": (_setting(default, "IPV6") or "").lower() == "yes",
        "policies": policies,
        "failure": None,
    }
    if st["enabled"] and service == "failed":
        st["failure"] = service_failure("ufw")
    st["headline"], st["level"], st["advice"] = _verdict(st)
    return st


def _verdict(st: dict) -> tuple[str, str, str]:
    kind = st["kind"]
    if kind in ("firewalld", "nftables"):
        return (f"Firewall: {kind} is in charge here.", "info",
                f"This dashboard controls ufw. {kind} is managing the firewall instead, so use its own tools "
                f"({'firewall-config' if kind == 'firewalld' else 'nft'}) to change rules.")
    if not st["installed"]:
        return ("No ufw firewall installed.", "critical",
                "Install it with 'sudo apt install ufw', then turn it on here. Ubuntu ships it but leaves it off.")
    if st["enabled"] is None:
        return ("Can't tell whether the firewall is on.", "warning",
                "ufw is installed but its settings file (/etc/ufw/ufw.conf) couldn't be read. 'sudo ufw status' answers directly.")
    if st["enabled"] is False:
        return ("Firewall is OFF.", "critical",
                "Anything listening on this laptop can be reached by every machine on the networks you join. "
                "Turning it on keeps the default: block what comes in, allow what goes out.")
    if st["service"] == "failed":
        why = f" The service reported: {st['failure']}." if st.get("failure") else ""
        return ("Firewall is set to ON, but it failed to start.", "warning",
                "Some rules may be loaded and others not (often the IPv6 half)." + why +
                " 'Restart firewall' reloads every rule; if it fails again, the message above says which rule file is wrong.")
    if st["enabled"] and st["service"] != "active":
        return ("Firewall is set to ON, but its service isn't running.", "warning",
                "Rules are not being enforced right now. 'Restart firewall' starts it again.")
    if st["policies"].get("incoming") == "allow":
        return ("Firewall is ON, but lets everything in.", "critical",
                "The default for incoming connections is 'allow', so it blocks nothing unless a rule says so. Set it to deny.")
    return ("Firewall is ON.", "ok",
            f"Incoming: {st['policies'].get('incoming') or '?'} by default. Outgoing: {st['policies'].get('outgoing') or '?'} by default. "
            "Only the rules below make exceptions.")


# ---------------------------------------------------------------- rules (what root reads back)
_RULE = re.compile(r"^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)(?:\s+(IN|OUT|FWD))?\s+(.+?)(?:\s+#\s*(.*))?$")


def fingerprint(line: str) -> str:
    """What the root script compares before deleting rule N, so a list that changed underneath can't delete the wrong rule."""
    return hashlib.sha256(line.rstrip().encode()).hexdigest()


def parse_numbered(text: str) -> dict:
    """`ufw status numbered` -> {active, rules: [...]}. Lines that aren't rules are ignored."""
    active = None
    rules = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.startswith("Status:"):
            active = line.split(":", 1)[1].strip() == "active"
            continue
        m = _RULE.match(line)
        if not m:
            continue
        num, to, action, direction, src, comment = m.groups()
        v6 = "(v6)" in to or "(v6)" in src
        rules.append({
            "num": int(num), "to": to.replace(" (v6)", "").strip(), "action": action.lower(),
            "direction": (direction or "IN").lower(), "from": src.replace(" (v6)", "").strip(), "v6": v6,
            "comment": (comment or "").strip(), "ours": (comment or "").startswith("LinuxGuardian"),
            "line": line, "fingerprint": fingerprint(line),
        })
    return {"active": active, "rules": rules}


def describe_rule(r: dict) -> str:
    who = "anyone" if r["from"].startswith("Anywhere") else r["from"]
    verb = {"allow": "Allows", "deny": "Blocks", "reject": "Refuses", "limit": "Rate-limits"}[r["action"]]
    if r["direction"] == "out":
        return f"{verb} this laptop connecting out to {r['to']}"
    return f"{verb} {who} reaching {r['to']}" + (" over IPv6" if r["v6"] else "")


# ---------------------------------------------------------------- adding a rule
def parse_port(text: str, proto: str) -> str:
    text = text.strip()
    m = re.fullmatch(r"(\d{1,5})(?::(\d{1,5}))?", text)
    if not m:
        raise ValueError(f"'{text}' isn't a port. Use a number such as 22, or a range such as 6000:6010.")
    lo = int(m.group(1))
    hi = int(m.group(2)) if m.group(2) else lo
    if not (1 <= lo <= 65535 and 1 <= hi <= 65535) or hi < lo:
        raise ValueError("Ports run from 1 to 65535, low end first.")
    if m.group(2):
        if proto == "any":
            raise ValueError("A port range needs a protocol: pick TCP or UDP (ufw requires it).")
        return f"{lo}:{hi}" if hi != lo else str(lo)
    return str(lo)


def parse_source(text: str) -> str:
    text = text.strip()
    if text.lower() in ("", "any", "anywhere"):
        return "any"
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ValueError(f"'{text}' isn't an IP address or network (or leave it empty for anyone).") from exc
    if net.prefixlen == 0:
        return "any"
    if net.is_multicast:
        raise ValueError(f"{net} is a multicast group, not a machine or network that can connect to you.")
    return str(net.network_address) if net.num_addresses == 1 else str(net)


def plan_add(action: str, port: str, proto: str = "tcp", source: str = "", label: str = "") -> dict:
    if action not in ACTIONS:
        raise ValueError(f"Unknown action '{action}'. Use one of: {', '.join(ACTIONS)}.")
    if proto not in PROTOS:
        raise ValueError(f"Unknown protocol '{proto}'. Use tcp, udp or any.")
    if action == "limit" and proto != "tcp":
        raise ValueError("Rate limiting only works for TCP (it counts new connections).")
    ports = parse_port(port, proto)
    src = parse_source(source)
    if not LABEL_RE.fullmatch(label.strip()):
        raise ValueError("Keep the label to 40 letters, digits, spaces, dots, dashes or underscores.")
    comment = "LinuxGuardian" + (f": {label.strip()}" if label.strip() else "")
    words = [action] + ([] if proto == "any" else ["proto", proto]) + ["from", src, "to", "any", "port", ports, "comment", comment]
    who = "anyone" if src == "any" else src
    what = f"{'TCP and UDP' if proto == 'any' else proto.upper()} port{'s' if ':' in ports else ''} {ports.replace(':', '-')}"
    effect = {
        "allow": f"Lets {who} connect to this laptop on {what}.",
        "deny": f"Silently drops connections from {who} to {what}.",
        "reject": f"Refuses connections from {who} to {what} (they are told straight away).",
        "limit": f"Lets {who} connect on {what}, but blocks an address that opens 6 or more connections in 30 seconds (slows password guessing).",
    }[action]
    warnings = []
    if action in ("allow", "limit") and src == "any":
        warnings.append("Open to anyone: every machine on every network this laptop joins (cafe, airport, hotel) can reach this port. "
                        "If only one machine or your home network needs it, put its address in 'From'.")
    if action == "allow" and ports in ("22", "3389", "5900", "23"):
        warnings.append("This is a remote-login port. Prefer 'limit' over 'allow', and allow it only from addresses you trust.")
    shown = " ".join(shlex.quote(w) for w in words)
    return {"action": action, "proto": proto, "ports": ports, "from": src, "label": label.strip(), "comment": comment,
            "words": words, "command": f"sudo ufw {shown}", "effect": effect, "warnings": warnings}


def render_plan(p: dict) -> str:
    lines = [p["effect"], "", "Command (what 'Add rule' runs):", f"  {p['command']}"]
    if p["warnings"]:
        lines += [""] + [f"Note: {w}" for w in p["warnings"]]
    lines += ["", "Nothing else changes: the default policy and every other rule stay as they are."]
    return "\n".join(lines)


# ---------------------------------------------------------------- what was blocked
_BLOCK = re.compile(r"\[UFW (BLOCK|AUDIT|ALLOW|LIMIT BLOCK)\] IN=(\S*) OUT=(\S*).*?SRC=(\S+) DST=(\S+).*?PROTO=(\S+)(?:.*?DPT=(\d+))?")


def recent_blocks(limit: int = 4000) -> dict:
    path = os.environ.get("LG_UFW_LOG", "/var/log/ufw.log")
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 600_000))
            tail = fh.read().decode(errors="replace").splitlines()[-limit:]
    except FileNotFoundError:
        return {"readable": False, "reason": "There is no ufw log yet (logging may be off, or nothing has been blocked).", "total": 0}
    except OSError:
        return {"readable": False, "reason": "The firewall log is only readable by administrators and the 'adm' group.", "total": 0}
    sources: Counter = Counter()
    ports: Counter = Counter()
    inbound = outbound = 0
    first = last = None
    for line in tail:
        m = _BLOCK.search(line)
        if not m or "BLOCK" not in m.group(1):
            continue
        _kind, iface_in, _iface_out, src, dst, proto, dport = m.groups()
        stamp = line[:15]
        first = first or stamp
        last = stamp
        if iface_in:
            inbound += 1
            sources[src] += 1
        else:
            outbound += 1
        ports[f"{proto.lower()}/{dport}" if dport else proto.lower()] += 1
    total = inbound + outbound
    return {"readable": True, "total": total, "inbound": inbound, "outbound": outbound, "first": first, "last": last,
            "top_sources": [{"addr": a, "count": c, "kind": _addr_kind(a)} for a, c in sources.most_common(8)],
            "top_ports": [{"port": p, "count": c} for p, c in ports.most_common(8)]}


def _addr_kind(addr: str) -> str:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "this laptop"
    return "internet" if ip.is_global else "local network"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--status", action="store_true")
    g.add_argument("--blocks", action="store_true")
    g.add_argument("--plan-add", action="store_true")
    g.add_argument("--parse-rules", action="store_true")
    ap.add_argument("--kind")
    ap.add_argument("--limit", type=int, default=4000)
    ap.add_argument("--action")
    ap.add_argument("--port")
    ap.add_argument("--proto", default="tcp")
    ap.add_argument("--from", dest="source", default="")
    ap.add_argument("--label", default="")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.status:
        st = status(a.kind)
        if a.json:
            print(json.dumps(st))
        else:
            pol = st["policies"]
            print(f"{st['headline']}\n{st['advice']}\nService: {st['service']}  Logging: {st['logging']}  "
                  f"Default incoming: {pol.get('incoming')}  outgoing: {pol.get('outgoing')}  routed: {pol.get('routed')}")
        return 0
    if a.blocks:
        b = recent_blocks(max(1, min(a.limit, 50_000)))
        if a.json:
            print(json.dumps(b))
        elif not b["readable"]:
            print(b["reason"])
        else:
            print(f"{b['total']} blocked ({b['inbound']} incoming, {b['outbound']} outgoing) between {b['first']} and {b['last']}")
            for s in b["top_sources"]:
                print(f"  {s['count']:>6}  from {s['addr']} ({s['kind']})")
            for p in b["top_ports"]:
                print(f"  {p['count']:>6}  to {p['port']}")
        return 0
    if a.parse_rules:
        parsed = parse_numbered(sys.stdin.read())
        if a.json:
            print(json.dumps(parsed))
        else:
            for r in parsed["rules"]:
                print(f"[{r['num']:>2}] {describe_rule(r)}  ({r['action']} {r['to']} from {r['from']})" + (f"  # {r['comment']}" if r["comment"] else ""))
        return 0
    if not a.action or not a.port:
        ap.error("--plan-add needs --action and --port")
    try:
        p = plan_add(a.action, a.port, a.proto, a.source, a.label)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(p) if a.json else render_plan(p))
    return 0


if __name__ == "__main__":
    sys.exit(main())

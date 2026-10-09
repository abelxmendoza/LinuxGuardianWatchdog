#!/usr/bin/env python3
"""What is listening on this machine, who can reach it, and how worried to be.

DETECTION ONLY. This never closes a port, stops a service, or changes the
firewall; it reads what the kernel reports and says what it means. The
"advice" it prints is text for a human to act on.

It needs no root, which sets honest limits that it reports rather than hides:
  * `ss -p` only names processes you own. Listeners owned by root or another
    user are shown as "owner not visible", not guessed at.
  * Firewall *rules* are root-only (`ufw status`, `iptables`, `nft` all refuse
    to run for a normal user). What IS readable: whether ufw is enabled, and
    its default inbound policy. So firewall coverage is reported as
    "default-deny, but allow-rules can't be checked" -- never "this port is
    blocked", because that can't be known without root.

Output modes:
  (default)   JSON lines: one {"type": "meta"} line, then {"type": "service"} lines.
  --text      Human-readable report.
  --summary   One `key=value` line (for shell scripts and the security audit).
  --record    Like default, and also writes a security event (events.py) for
              each exposure that is NEW or CHANGED since the last --record.

Test hooks (inputs only): LG_UFW_CONF, LG_UFW_DEFAULTS, LG_HOME.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
UI_DIR = SUITE_DIR.parent / "LinuxGuardianSuiteUI"
for _p in (SUITE_DIR, UI_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from events import lg_home, record_event  # noqa: E402
from linuxguardian_ui.process_catalog import explain  # noqa: E402

# --- service classes ---------------------------------------------------------
REMOTE_CONTROL = "remote_control"  # hands over your screen/keyboard/shell
ADMIN = "admin"                    # control APIs that effectively run code
DATABASE = "database"
REMOTE_LOGIN = "remote_login"
WEB = "web"
MAIL = "mail"
PRINTING = "printing"
DNS = "dns"
DISCOVERY = "discovery"            # mDNS, DHCP, SSDP...: normal LAN chatter
VPN = "vpn"
ROBOTICS = "robotics"
UNKNOWN = "unknown"

SEV_ORDER = {"info": 0, "warning": 1, "critical": 2}

# (proto, port) -> (label, class). Ranges are handled in classify_port().
KNOWN_PORTS: dict[tuple[str, int], tuple[str, str]] = {
    ("tcp", 21): ("FTP", REMOTE_LOGIN),
    ("tcp", 22): ("SSH", REMOTE_LOGIN),
    ("tcp", 23): ("Telnet", REMOTE_CONTROL),
    ("tcp", 25): ("Mail (SMTP)", MAIL),
    ("tcp", 53): ("DNS", DNS),
    ("udp", 53): ("DNS", DNS),
    ("tcp", 80): ("Web server", WEB),
    ("tcp", 443): ("Web server (HTTPS)", WEB),
    ("tcp", 631): ("Printing (CUPS)", PRINTING),
    ("tcp", 3000): ("Web dev server", WEB),
    ("tcp", 3306): ("MySQL", DATABASE),
    ("tcp", 3389): ("Remote Desktop (RDP)", REMOTE_CONTROL),
    ("tcp", 5000): ("Web dev server", WEB),
    ("tcp", 5037): ("Android Debug Bridge", ADMIN),
    ("tcp", 5173): ("Web dev server", WEB),
    ("tcp", 5432): ("PostgreSQL", DATABASE),
    ("tcp", 6379): ("Redis", DATABASE),
    ("tcp", 8000): ("Web dev server", WEB),
    ("tcp", 8008): ("Web server", WEB),
    ("tcp", 8080): ("Web server", WEB),
    ("tcp", 8443): ("Web server (HTTPS)", WEB),
    ("tcp", 8765): ("Foxglove bridge", ROBOTICS),
    ("tcp", 8888): ("Jupyter notebook (or similar)", ADMIN),
    ("tcp", 9200): ("Elasticsearch", DATABASE),
    ("tcp", 11211): ("Memcached", DATABASE),
    ("tcp", 11311): ("ROS 1 master", ROBOTICS),
    ("tcp", 11434): ("Ollama LLM API", ADMIN),
    ("tcp", 27017): ("MongoDB", DATABASE),
    ("tcp", 2375): ("Docker API (unencrypted)", ADMIN),
    ("tcp", 2376): ("Docker API", ADMIN),
    ("udp", 67): ("DHCP", DISCOVERY),
    ("udp", 68): ("DHCP client", DISCOVERY),
    ("udp", 123): ("Time sync (NTP)", DISCOVERY),
    ("udp", 137): ("NetBIOS name service", DISCOVERY),
    ("udp", 138): ("NetBIOS datagrams", DISCOVERY),
    ("udp", 161): ("SNMP", ADMIN),
    ("udp", 1900): ("UPnP / SSDP discovery", DISCOVERY),
    ("udp", 5353): ("mDNS / Bonjour discovery", DISCOVERY),
    ("udp", 14540): ("MAVLink (PX4)", ROBOTICS),
    ("udp", 14550): ("MAVLink (PX4)", ROBOTICS),
    ("udp", 41641): ("Tailscale", VPN),
    ("udp", 51820): ("WireGuard", VPN),
}


def classify_port(proto: str, port: int) -> tuple[str, str]:
    """(label, class) for a listening port; ('Unknown service', UNKNOWN) if unrecognized."""
    if proto == "tcp" and 5900 <= port <= 5909:
        return "VNC remote desktop", REMOTE_CONTROL
    if proto == "udp" and 7400 <= port <= 7699:
        return "ROS 2 / DDS discovery", ROBOTICS
    return KNOWN_PORTS.get((proto, port), ("Unknown service", UNKNOWN))


CLASS_NOTES = {
    REMOTE_CONTROL: (
        "Remote-control service: whoever can reach this port and gets past its login can use your "
        "screen, keyboard or shell. VNC logins are weak (about 8 characters) and unencrypted unless configured."
    ),
    ADMIN: "A control interface that can effectively run code or commands on this machine.",
    DATABASE: "A database. These are meant to listen on this machine only; reachable from a network they are a classic breach.",
    REMOTE_LOGIN: "A remote login service. Normal if you use it, but it should be a deliberate choice.",
    WEB: "A web server. Fine for development on this machine only; on all interfaces anyone on the network can browse it.",
    MAIL: "A mail server. Rarely needed on a laptop.",
    PRINTING: "Printer sharing/discovery.",
    DNS: "A DNS service.",
    DISCOVERY: "Normal local-network discovery chatter.",
    VPN: "VPN transport (expected if you use it).",
    ROBOTICS: (
        "Typical for robotics. ROS 2 discovery is open by default, so other machines on the same network can "
        "see (and talk to) your ROS graph unless a firewall or ROS_LOCALHOST_ONLY=1 restricts it."
    ),
    UNKNOWN: "Not a service this tool recognizes.",
}


# --- addresses and interfaces ------------------------------------------------
def parse_address(text: str) -> tuple[str, str, int | None]:
    """'0.0.0.0:5900' | '[::]:5900' | '127.0.0.53%lo:53' | '*:5900' -> (host, iface, port).

    port is None for '*' (unknown). host '*' means wildcard.
    """
    text = text.strip()
    if ":" not in text:
        return text, "", None
    left, _, port_s = text.rpartition(":")
    port = int(port_s) if port_s.isdigit() else None
    iface = ""
    if left.startswith("["):
        end = left.find("]")
        host = left[1:end]
        rest = left[end + 1 :]
        if rest.startswith("%"):
            iface = rest[1:]
    else:
        host, _, iface = left.partition("%")
    if "%" in host:  # e.g. [fe80::1%eth0]
        host, _, iface = host.partition("%")
    return host, iface, port


def is_wildcard(host: str) -> bool:
    return host in ("0.0.0.0", "::", "*", "")


def parse_ss_listeners(text: str) -> list[dict]:
    """Parse `ss -H -tulnp`. Keeps TCP LISTEN and UDP UNCONN sockets only."""
    listeners: list[dict] = []
    for line in text.splitlines():
        # maxsplit: the process column can contain spaces ("Isolated Web Co").
        fields = line.split(None, 6)
        if len(fields) < 6:
            continue
        netid, state, _rq, _sq, local, _peer = fields[:6]
        rest = fields[6] if len(fields) > 6 else ""
        if not ((netid == "tcp" and state == "LISTEN") or (netid == "udp" and state == "UNCONN")):
            continue
        host, iface, port = parse_address(local)
        if port is None:
            continue
        procs = [(m[0], int(m[1])) for m in re.findall(r'\("([^"]*)",pid=(\d+)', rest)]
        listeners.append({"proto": netid, "host": host, "iface": iface, "port": port, "procs": procs})
    return listeners


def parse_established(text: str) -> dict[int, list[str]]:
    """`ss -H -tn state established` -> {local_port: [peer addresses]}."""
    peers: dict[int, list[str]] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        _h, _i, lport = parse_address(fields[2])
        phost, _pi, _pp = parse_address(fields[3])
        if lport is None:
            continue
        bucket = peers.setdefault(lport, [])
        if phost not in bucket:
            bucket.append(phost)
    return peers


def _kind_of(addr: str, iface: str) -> str:
    ip = ipaddress.ip_address(addr)
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return "vpn"  # CGNAT range: Tailscale and friends
    if iface.startswith(("tailscale", "wg", "tun", "zt")):
        return "vpn"
    if ip.is_private:
        return "private"
    return "public"


def interfaces_from_ip_json(text: str) -> list[dict]:
    """`ip -j addr` -> one entry per address on an UP interface."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    found: list[dict] = []
    for link in data:
        if link.get("operstate") == "DOWN":
            continue
        iface = link.get("ifname", "")
        for info in link.get("addr_info", []):
            addr = info.get("local")
            if not addr:
                continue
            try:
                prefix = int(info.get("prefixlen", 32 if info.get("family") == "inet" else 128))
                network = str(ipaddress.ip_interface(f"{addr}/{prefix}").network)
                kind = _kind_of(addr, iface)
            except ValueError:
                continue
            found.append({"iface": iface, "addr": addr, "cidr": network, "kind": kind})
    return found


def reachable_networks(scope: str, bind_host: str, interfaces: list[dict]) -> list[dict]:
    """Which networks can see a listener bound this way."""
    usable = [i for i in interfaces if i["kind"] not in ("loopback", "link_local")]
    if scope == "all":
        return usable
    if scope == "interface":
        return [i for i in usable if i["addr"] == bind_host]
    return []


def bind_scope(host: str) -> str:
    if is_wildcard(host):
        return "all"
    try:
        if ipaddress.ip_address(host).is_loopback:
            return "loopback"
    except ValueError:
        pass
    return "interface"


# --- firewall ----------------------------------------------------------------
def _run(cmd: list[str], timeout: float) -> str | None:
    env = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout


def firewall_status() -> dict:
    """What can be known about the firewall WITHOUT root.

    state: active | inactive | none      kind: ufw | firewalld | nftables | none
    coverage: default_deny | permissive | unknown | none
    rules_readable: whether per-port allow-rules could be inspected (needs root)
    """
    conf = Path(os.environ.get("LG_UFW_CONF", "/etc/ufw/ufw.conf"))
    defaults = Path(os.environ.get("LG_UFW_DEFAULTS", "/etc/default/ufw"))

    def active(unit: str) -> bool:
        return (_run(["systemctl", "is-active", unit], 10) or "").strip() == "active"

    enabled: bool | None = None
    try:
        m = re.search(r"^ENABLED=(\w+)", conf.read_text(), re.M)
        if m:
            enabled = m.group(1).lower() == "yes"
    except OSError:
        pass

    if enabled and active("ufw"):
        policy = ""
        try:
            m = re.search(r'^DEFAULT_INPUT_POLICY="?(\w+)"?', defaults.read_text(), re.M)
            policy = m.group(1).upper() if m else ""
        except OSError:
            pass
        coverage = {"DROP": "default_deny", "REJECT": "default_deny", "ACCEPT": "permissive"}.get(policy, "unknown")
        rules_readable = os.access("/etc/ufw/user.rules", os.R_OK)
        note = {
            "default_deny": "ufw is on and drops unsolicited inbound traffic by default.",
            "permissive": "ufw is on but its default is to ALLOW inbound traffic.",
            "unknown": "ufw is on; its default inbound policy couldn't be read.",
        }[coverage]
        if not rules_readable:
            note += " Individual allow-rules can't be read without root, so a specific port may still be open."
        return {"state": "active", "kind": "ufw", "coverage": coverage, "rules_readable": rules_readable, "note": note}
    # Rule out every running firewall BEFORE concluding "off": ufw can be
    # installed-but-disabled on a machine that uses firewalld or nftables.
    if active("firewalld"):
        return {
            "state": "active", "kind": "firewalld", "coverage": "unknown", "rules_readable": False,
            "note": "firewalld is running; its zones can't be read without root.",
        }
    if active("nftables"):
        return {
            "state": "active", "kind": "nftables", "coverage": "unknown", "rules_readable": False,
            "note": "The nftables service is running; its rules can't be read without root.",
        }
    if enabled is False:
        return {
            "state": "inactive", "kind": "ufw", "coverage": "none", "rules_readable": False,
            "note": "ufw is installed but turned off; nothing filters inbound traffic.",
        }
    return {
        "state": "none", "kind": "none", "coverage": "none", "rules_readable": False,
        "note": "No firewall service was detected (rules set by other means can't be seen without root).",
    }


# --- severity ----------------------------------------------------------------
def base_severity(proto: str, cls: str) -> str:
    """Severity of a listener reachable beyond this machine, before the firewall is considered."""
    if cls in (REMOTE_CONTROL, ADMIN, DATABASE):
        return "critical" if proto == "tcp" else "warning"
    if proto == "udp":
        return "info"
    if cls in (VPN, DISCOVERY):
        return "info"
    return "warning"  # remote login, web, mail, printing, dns, robotics, unknown over TCP


def lower(sev: str) -> str:
    return {"critical": "warning", "warning": "info"}.get(sev, sev)


def final_severity(proto: str, cls: str, scope: str, networks: list[dict], fw: dict) -> str:
    """Severity after scope and firewall. Loopback is never a finding."""
    if scope == "loopback":
        return "info"
    sev = base_severity(proto, cls)
    # Reachable only over a VPN you control: one step down.
    if scope == "interface" and networks and all(n["kind"] == "vpn" for n in networks):
        sev = lower(sev)
    # A default-deny firewall is real mitigation but unverifiable (allow-rules
    # need root), so it lowers the level by one; it never makes it disappear.
    if fw.get("state") == "active" and fw.get("coverage") == "default_deny":
        sev = lower(sev)
    return sev


def advice_for(cls: str, process: str | None, proto: str, port: int) -> str:
    if process == "vino-server":
        return ("Turn it off in Settings > Sharing > Screen Sharing. If you do use it, enable the "
                "confirmation prompt and encryption there.")
    if cls == REMOTE_CONTROL:
        return "Stop the service if you don't use it, or restrict it to your own network with a firewall rule."
    if cls == ROBOTICS and proto == "udp":
        return "Normal for ROS 2. To keep discovery on this machine, set ROS_LOCALHOST_ONLY=1 for your ROS processes."
    if cls in (DISCOVERY, VPN):
        return "Nothing to do; this is expected."
    return ("If other machines don't need it: stop the service, or set it to listen on 127.0.0.1 only. "
            "If they do: allow just the machines you trust in your firewall.")


# --- assembling the report ---------------------------------------------------
def _proc_details(pid: int) -> tuple[str, str]:
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except OSError:
        cmdline = ""
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = ""
    return cmdline, exe


def build_services(
    listeners: list[dict], established: dict[int, list[str]], interfaces: list[dict], fw: dict
) -> list[dict]:
    """Merge dual-stack/duplicate sockets into one finding per (proto, port, owner)."""
    groups: dict[tuple, dict] = {}
    rank = {"loopback": 1, "interface": 2, "all": 3}
    for lst in listeners:
        proc = lst["procs"][0] if lst["procs"] else (None, None)
        key = (lst["proto"], lst["port"], proc[0])
        scope = bind_scope(lst["host"])
        g = groups.setdefault(key, {"proto": lst["proto"], "port": lst["port"], "process": proc[0],
                                    "pid": proc[1], "binds": [], "scope": scope})
        bind = {"host": lst["host"], "iface": lst["iface"]}
        if bind not in g["binds"]:
            g["binds"].append(bind)
        if rank[scope] > rank[g["scope"]]:
            g["scope"] = scope

    services: list[dict] = []
    for g in groups.values():
        label, cls = classify_port(g["proto"], g["port"])
        # Widest bind decides who can reach it.
        wide = next((b for b in g["binds"] if bind_scope(b["host"]) == g["scope"]), g["binds"][0])
        nets = reachable_networks(g["scope"], wide["host"], interfaces)
        sev = final_severity(g["proto"], cls, g["scope"], nets, fw)

        friendly, description = (None, None)
        if g["process"]:
            cmdline, exe = _proc_details(g["pid"]) if g["pid"] else ("", "")
            friendly, description = explain(g["process"], "system", str(g["pid"] or ""), cmdline, exe)

        reasons: list[str] = []
        if g["scope"] == "loopback":
            reasons.append("Only reachable from this laptop itself.")
        else:
            if g["scope"] == "all":
                where = ", ".join(f"{n['iface']} ({n['cidr']})" for n in nets) or "its networks"
                reasons.append(f"Listening on ALL network interfaces, so anything on {where} can try to connect.")
            else:
                where = ", ".join(f"{n['iface']} ({n['cidr']})" for n in nets) or wide["host"]
                reasons.append(f"Listening only on {wide['host']}, reachable via {where}.")
            if any(n["kind"] == "public" for n in nets):
                reasons.append("This machine has a public IP address, so this may be reachable from the internet.")
            reasons.append(CLASS_NOTES[cls])
            # Firewall context only matters for things worth a decision; repeating
            # it under every routine discovery port just buries the real finding.
            if sev != "info":
                if fw["state"] == "inactive":
                    reasons.append("No firewall is active, so nothing stands between this service and the network.")
                elif fw["state"] == "none":
                    reasons.append("No firewall service was detected.")
                else:
                    reasons.append(fw["note"])
        if not g["process"]:
            reasons.append("The owner isn't one of your processes (root or another user), so its name can't be shown without root.")

        services.append(
            {
                "type": "service",
                "id": f"{g['proto']}:{g['port']}:{g['process'] or 'unknown'}",
                "proto": g["proto"],
                "port": g["port"],
                "label": label,
                "class": cls,
                "severity": sev,
                "scope": g["scope"],
                "binds": g["binds"],
                "process": g["process"],
                "pid": g["pid"],
                "friendly": friendly,
                "description": description,
                "owner_known": bool(g["process"]),
                "reachable_via": nets,
                "peers": established.get(g["port"], []) if g["proto"] == "tcp" else [],
                "reasons": reasons,
                "advice": advice_for(cls, g["process"], g["proto"], g["port"]),
            }
        )
    services.sort(key=lambda s: (-SEV_ORDER[s["severity"]], s["scope"] == "loopback", s["port"]))
    return services


def collect() -> tuple[dict, list[dict]]:
    ss_ok = shutil.which("ss") is not None
    listeners_txt = _run(["ss", "-H", "-tulnp"], 20) if ss_ok else None
    est_txt = _run(["ss", "-H", "-tn", "state", "established"], 20) if ss_ok else None
    ip_txt = _run(["ip", "-j", "addr"], 10) if shutil.which("ip") else None

    interfaces = interfaces_from_ip_json(ip_txt or "[]")
    fw = firewall_status()
    services = build_services(
        parse_ss_listeners(listeners_txt or ""), parse_established(est_txt or ""), interfaces, fw
    )
    exposed = [s for s in services if s["scope"] != "loopback"]
    counts = {sev: sum(1 for s in exposed if s["severity"] == sev) for sev in SEV_ORDER}
    meta = {
        "type": "meta",
        "ss_ok": ss_ok and listeners_txt is not None,
        "root": hasattr(os, "geteuid") and os.geteuid() == 0,
        "firewall": fw,
        "networks": [i for i in interfaces if i["kind"] not in ("loopback", "link_local")],
        "counts": {**counts, "loopback": sum(1 for s in services if s["scope"] == "loopback")},
        "listeners": len(services),
        "owners_hidden": sum(1 for s in services if not s["owner_known"]),
    }
    return meta, services


# --- events ------------------------------------------------------------------
def _state_path() -> Path:
    return lg_home() / "state" / "exposure.json"


def record_new_exposures(services: list[dict]) -> list[Path]:
    """Write an event for every warning/critical exposure that is new or whose
    severity changed since the previous call. Unchanged ones stay quiet, so
    running this daily doesn't bury the timeline in repeats. An exposure that
    goes away and later returns counts as new again."""
    path = _state_path()
    try:
        previous = json.loads(path.read_text())
        if not isinstance(previous, dict):
            previous = {}
    except (OSError, json.JSONDecodeError):
        previous = {}

    current: dict[str, str] = {}
    written: list[Path] = []
    for s in services:
        if s["scope"] == "loopback" or SEV_ORDER[s["severity"]] < SEV_ORDER["warning"]:
            continue
        current[s["id"]] = s["severity"]
        if previous.get(s["id"]) == s["severity"]:
            continue
        who = s["friendly"] or s["process"] or "an unidentified process"
        changed = s["id"] in previous
        written.append(
            record_event(
                "network",
                s["severity"],
                "exposure_changed" if changed else "exposed_service",
                f"{s['label']} ({who}) is listening on {s['proto']}/{s['port']} "
                f"and is reachable from the network [{s['severity']}].",
                status="changed" if changed else "detected",
                process=s["process"],
                pid=s["pid"],
                port=s["port"],
                protocol=s["proto"],
                service=s["label"],
            )
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(current, indent=1))
    os.replace(tmp, path)
    return written


# --- rendering ---------------------------------------------------------------
def top_exposure(services: list[dict]) -> dict | None:
    for s in services:
        if s["scope"] != "loopback" and s["severity"] != "info":
            return s
    return None


def render_summary(meta: dict, services: list[dict]) -> str:
    c, fw = meta["counts"], meta["firewall"]
    top = top_exposure(services)
    top_s = "-"
    if top:
        name = (top["process"] or top["label"]).replace(" ", "_")
        top_s = f"{name}:{top['port']}/{top['proto']}"
    return " ".join(
        [
            f"critical={c['critical']}",
            f"warning={c['warning']}",
            f"info={c['info']}",
            f"loopback={c['loopback']}",
            f"listeners={meta['listeners']}",
            f"firewall={fw['kind']}",
            f"fw_state={fw['state']}",
            f"coverage={fw['coverage']}",
            f"top={top_s}",
            f"ss_ok={1 if meta['ss_ok'] else 0}",
        ]
    )


def render_text(meta: dict, services: list[dict]) -> str:
    fw = meta["firewall"]
    c = meta["counts"]
    exposed = [s for s in services if s["scope"] != "loopback"]
    attention = [s for s in exposed if s["severity"] != "info"]
    routine = [s for s in exposed if s["severity"] == "info"]
    local_only = [s for s in services if s["scope"] == "loopback"]

    def who(s: dict) -> str:
        return s["friendly"] or s["process"] or "owner not visible"

    lines = [
        f"Firewall: {fw['kind']} {fw['state']}. {fw['note']}",
        "Networks this machine is on: "
        + (", ".join(f"{n['iface']} {n['addr']} ({n['kind']})" for n in meta["networks"]) or "none"),
        f"Reachable beyond this machine: {c['critical']} critical, {c['warning']} warning, {c['info']} routine"
        f"  |  loopback-only: {c['loopback']}",
        "",
    ]
    if attention:
        lines.append(f"Needs your attention ({len(attention)}):")
        for s in attention:
            lines.append(f"[{s['severity'].upper()}] {s['label']}  {s['proto']}/{s['port']}  ({who(s)})")
            lines.extend(f"    - {r}" for r in s["reasons"])
            lines.append(f"    Connected now: {', '.join(s['peers']) if s['peers'] else 'nobody'}")
            lines.append(f"    If you don't need it: {s['advice']}")
    else:
        lines.append("Nothing reachable from the network needs your attention.")
    if routine:
        lines.append("")
        lines.append(f"Other listeners reachable from the network ({len(routine)}, routine):")
        for s in routine:
            lines.append(f"  {s['proto']}/{s['port']:<6} {s['label']}  ({who(s)})")
    if local_only:
        lines.append("")
        lines.append(f"Only reachable from this laptop ({len(local_only)}): "
                     + ", ".join(f"{s['proto']}/{s['port']}" for s in local_only))
    if meta["owners_hidden"]:
        lines.append("")
        lines.append(f"{meta['owners_hidden']} listener(s) belong to root or another user; run as root to see which.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--text", action="store_true", help="human-readable report")
    parser.add_argument("--summary", action="store_true", help="one key=value line")
    parser.add_argument("--record", action="store_true", help="also record events for NEW/CHANGED exposures")
    args = parser.parse_args()

    meta, services = collect()
    if args.record:
        recorded = record_new_exposures(services)
        meta["events_recorded"] = len(recorded)
    if args.summary:
        print(render_summary(meta, services))
    elif args.text:
        print(render_text(meta, services))
        if args.record:
            print(f"\nRecorded {meta['events_recorded']} new security event(s).")
    else:
        print(json.dumps(meta, ensure_ascii=False))
        for s in services:
            print(json.dumps(s, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""VPN status and diagnostics for Tailscale and Proton VPN, together or alone. (read-only, no root)

Answers the questions that matter when two VPNs share one laptop:
  * is each one actually connected, and healthy?
  * where does your internet traffic REALLY go (which interface owns the default route)?
  * can you still reach your Tailscale devices while the other VPN is on?
  * could DNS or IPv6 traffic be leaking around the tunnel?
  * are the two fighting over addresses, or is a Tailscale exit node stacked on another VPN?

Everything is read from the machine (tailscale, nmcli, ip, resolvectl). Nothing is sent anywhere unless you
ask for the optional public-IP check, which makes one request to Cloudflare's trace page.

  vpn_status.py [--json|--text]  [--public-ip]  [--tailscale-ping]

Test hooks: PATH stubs for tailscale/nmcli/ip/resolvectl/dpkg-query.
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
import urllib.request

CGNAT = ipaddress.ip_network("100.64.0.0/10")
TAILSCALE_DNS_IP = "100.100.100.100"
KILLSWITCH_PREFIXES = ("pvpn-killswitch", "pvpn-routed-killswitch", "pvpn-ipv6leak", "ipv6leakintrf0")


def _run(cmd: list[str], timeout: float = 10) -> tuple[int, str]:
    env = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    return p.returncode, p.stdout


# ---------------------------------------------------------------- Tailscale
def parse_tailscale(raw: str) -> dict:
    """`tailscale status --json` -> the few facts that matter."""
    try:
        d = json.loads(raw)
    except json.JSONDecodeError:
        return {"installed": True, "state": "unknown"}
    peers = d.get("Peer") or {}
    me = d.get("Self") or {}
    return {
        "installed": True,
        "state": d.get("BackendState") or "unknown",             # Running | NeedsLogin | Stopped | Starting ...
        "online": bool(me.get("Online")),
        "tailnet": (d.get("CurrentTailnet") or {}).get("Name") or d.get("MagicDNSSuffix") or "",
        "ips": d.get("TailscaleIPs") or [],
        "peers_total": len(peers),
        "peers_online": sum(1 for p in peers.values() if p.get("Online")),
        "peer_ips_online": [ip for p in peers.values() if p.get("Online") for ip in (p.get("TailscaleIPs") or [])[:1]],
        "exit_node": bool(d.get("ExitNodeStatus")),
        "exit_node_name": ((d.get("ExitNodeStatus") or {}).get("TailscaleIPs") or [""])[0] if d.get("ExitNodeStatus") else "",
        "health": [str(h) for h in (d.get("Health") or [])],
    }


def tailscale_status() -> dict:
    if not shutil.which("tailscale"):
        return {"installed": False, "state": "absent"}
    rc, out = _run(["tailscale", "status", "--json"])
    if rc != 0 or not out.strip():
        return {"installed": True, "state": "unknown"}
    return parse_tailscale(out)


# ------------------------------------------------------------------- Proton
def parse_nm_connections(text: str) -> list[dict]:
    """`nmcli -t -f NAME,UUID,TYPE,DEVICE connection show` -> rows. Terse mode escapes ':' in names as '\\:'."""
    rows = []
    for line in text.splitlines():
        parts = re.split(r"(?<!\\):", line)
        if len(parts) < 4:
            continue
        name, _uuid, ctype, device = (p.replace("\\:", ":") for p in parts[:4])
        rows.append({"name": name, "type": ctype, "device": device, "active": bool(device)})
    return rows


def is_proton_name(name: str) -> bool:
    n = name.lower()
    return n.startswith(("protonvpn", "proton vpn", "proton-vpn", "proton_vpn")) or n.startswith("pvpn-") or n == "proton0"


def proton_status() -> dict:
    rc, pk = _run(["dpkg-query", "-W", "-f", "${Package}\t${Status}\n"])
    packages = sorted({line.split("\t")[0] for line in pk.splitlines()
                       if "installed" in line and re.match(r"^(proton-?vpn|protonvpn)", line.split("\t")[0], re.I)}) if rc == 0 else []
    rc, nm = _run(["nmcli", "-t", "-f", "NAME,UUID,TYPE,DEVICE", "connection", "show"])
    conns = parse_nm_connections(nm) if rc == 0 else []
    proton = [c for c in conns if is_proton_name(c["name"]) and not c["name"].lower().startswith("pvpn-")]
    kill = [c for c in conns if c["name"].lower().startswith(KILLSWITCH_PREFIXES) or c["device"] == "ipv6leakintrf0"]
    active = [c for c in proton if c["active"]]
    # Also look at the network interfaces themselves: the app may bring the tunnel up in a way NetworkManager doesn't list.
    rc, links = _run(["ip", "-o", "link", "show"])
    tunnels = re.findall(r"^\d+:\s+(proton\d*|pvpn\w*)[:@]\s.*<([^>]*)>", links, re.M) if rc == 0 else []
    live = [name for name, flags in tunnels if "UP" in flags.split(",") and "LOWER_UP" in flags.split(",")]
    connected = bool(active) or bool(live)
    device = active[0]["device"] if active else (live[0] if live else "")
    return {
        "installed": bool(packages) or bool(proton) or bool(kill) or bool(tunnels),
        "packages": packages,
        "connected": connected,
        "connection": active[0]["name"] if active else (f"tunnel {live[0]}" if live else ""),
        "device": device,
        "killswitch_present": bool(kill),
        "killswitch_names": [c["name"] for c in kill],
        "nm_available": rc == 0,
    }


# ------------------------------------------------------------------ network
def parse_default_routes(text: str) -> list[dict]:
    routes = []
    for line in text.splitlines():
        m = re.match(r"^default\s+(?:via\s+(\S+)\s+)?dev\s+(\S+)", line.strip())
        if m:
            routes.append({"via": m.group(1) or "", "dev": m.group(2)})
    return routes


def route_dev(addr: str) -> str:
    rc, out = _run(["ip", "route", "get", addr])
    m = re.search(r"\bdev\s+(\S+)", out) if rc == 0 else None
    return m.group(1) if m else ""


def interface_addrs() -> dict[str, list[str]]:
    rc, out = _run(["ip", "-o", "addr", "show"])
    result: dict[str, list[str]] = {}
    if rc != 0:
        return result
    for line in out.splitlines():
        m = re.match(r"^\d+:\s+(\S+)\s+inet6?\s+(\S+)", line)
        if m:
            result.setdefault(m.group(1).rstrip(":"), []).append(m.group(2).split("/")[0])
    return result


def cgnat_overlaps(addrs: dict[str, list[str]]) -> list[str]:
    """Interfaces other than Tailscale's that hold an address in Tailscale's 100.64.0.0/10 range."""
    bad = []
    for dev, ips in addrs.items():
        if dev.startswith("tailscale") or dev == "lo":
            continue
        for ip in ips:
            try:
                if ipaddress.ip_address(ip) in CGNAT:
                    bad.append(dev)
                    break
            except ValueError:
                continue
    return bad


def parse_resolvectl(text: str) -> dict[str, dict]:
    """Per-link DNS facts from `resolvectl status`."""
    links: dict[str, dict] = {}
    cur = None
    last_key = ""
    for line in text.splitlines():
        m = re.match(r"^Link \d+ \((\S+)\)", line)
        if m:
            cur = links.setdefault(m.group(1), {"servers": [], "domains": [], "default_route": False})
            last_key = ""
            continue
        if cur is None:
            continue
        s = line.strip()
        if "Protocols:" in s:
            cur["default_route"] = "+DefaultRoute" in s
            last_key = ""
        elif s.startswith("DNS Servers:"):
            cur["servers"] += s.split(":", 1)[1].split()
            last_key = "servers"
        elif s.startswith("DNS Domain:"):
            cur["domains"] += s.split(":", 1)[1].split()
            last_key = "domains"
        elif last_key and s and ":" not in s.split()[0]:
            cur[last_key] += s.split()                      # wrapped continuation line
        else:
            last_key = ""
    return links


def dns_owner(links: dict[str, dict]) -> str:
    """Which link receives general DNS queries: the one with the '~.' routing domain, else a DefaultRoute link."""
    for dev, info in links.items():
        if "~." in info["domains"]:
            return dev
    for dev, info in links.items():
        if info["default_route"] and info["servers"]:
            return dev
    return ""


# -------------------------------------------------------------- optional probes
def public_ip() -> dict:
    """ONE request to Cloudflare's trace page (only when asked). Returns {'ip','loc'} or {'error'}."""
    try:
        with urllib.request.urlopen("https://1.1.1.1/cdn-cgi/trace", timeout=6) as r:  # noqa: S310 - fixed https URL
            body = r.read().decode("ascii", "replace")
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)[:120]}
    kv = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
    return {"ip": kv.get("ip", ""), "loc": kv.get("loc", "")}


def tailscale_ping(ip: str) -> dict:
    if not re.fullmatch(r"[0-9a-fA-F:.]+", ip or ""):
        return {"ok": False, "detail": "no peer to test"}
    rc, out = _run(["tailscale", "ping", "--c", "1", "--timeout", "5s", ip], timeout=12)
    return {"ok": rc == 0 and "pong" in out.lower(), "detail": out.strip().splitlines()[-1] if out.strip() else "no answer"}


# ---------------------------------------------------------------------- verdicts
def analyse(ts: dict, px: dict, net: dict) -> list[dict]:
    """Plain-language findings: [{'level': ok|attention|info, 'title', 'detail', 'advice'}]."""
    out: list[dict] = []

    def add(level: str, title: str, detail: str = "", advice: str = "") -> None:
        out.append({"level": level, "title": title, "detail": detail, "advice": advice})

    # Tailscale on its own
    if not ts.get("installed"):
        add("info", "Tailscale isn't installed")
    elif ts["state"] == "Running" and ts.get("online"):
        add("ok", f"Tailscale is connected ({ts.get('peers_online', 0)} of {ts.get('peers_total', 0)} devices online)",
            f"Network: {ts.get('tailnet') or 'your tailnet'}")
    elif ts["state"] == "NeedsLogin":
        add("attention", "Tailscale needs you to sign in", advice="Run: sudo tailscale up")
    elif ts["state"] in ("Stopped", "NoState"):
        add("attention", "Tailscale is turned off", advice="Run: sudo tailscale up")
    elif ts["state"] == "Running":
        add("attention", "Tailscale says it's running but this laptop is offline in your tailnet",
            advice="Check your internet connection, then: tailscale status")
    else:
        add("info", f"Couldn't read Tailscale's status ({ts['state']})", advice="Try: tailscale status")
    for h in ts.get("health", []):
        add("attention", "Tailscale reports a problem", h)

    # Proton on its own
    if not px.get("installed"):
        add("info", "Proton VPN not detected (not installed, or not connected through NetworkManager)")
    elif px["connected"]:
        add("ok", f"Proton VPN is connected ({px['connection']})")
    else:
        add("info", "Proton VPN is installed but not connected")
    if px.get("killswitch_present") and not px.get("connected"):
        add("attention", "Proton's kill switch is armed while Proton is disconnected",
            "While it's armed your normal internet access is blocked on purpose: " + ", ".join(px["killswitch_names"]),
            "Reconnect Proton, or turn the kill switch off in the Proton app. If you uninstalled Proton, delete the leftover "
            "connections: nmcli connection delete <name>")

    both = ts.get("state") == "Running" and px.get("connected")
    ts_dev = net.get("tailscale_route_dev", "")
    if ts.get("state") == "Running" and ts_dev and not ts_dev.startswith("tailscale"):
        add("attention", "Traffic to your Tailscale devices isn't using Tailscale",
            f"Your laptop would send it out through '{ts_dev}'.",
            "Most often another VPN or its kill switch is catching the 100.x.x.x range. Allow 100.64.0.0/10 (or Tailscale) "
            "in the other VPN's settings, or disconnect it while using Tailscale.")
    elif both and ts_dev:
        add("ok", "Tailscale and Proton are both up, and Tailscale traffic still goes through Tailscale")

    # Routing
    default_dev = net.get("internet_route_dev", "")
    if px.get("connected") and default_dev:
        if default_dev == px["device"] or default_dev.startswith(("proton", "wg", "tun", "pvpn")):
            add("ok", f"Your internet traffic goes through Proton ({default_dev})")
        elif default_dev.startswith("tailscale"):
            add("attention", "Your internet traffic is going through a Tailscale exit node, not Proton",
                advice="Pick one: turn the exit node off (tailscale set --exit-node=) or disconnect Proton.")
        else:
            add("attention", f"Proton says it's connected, but your internet traffic leaves through '{default_dev}'",
                "That means the tunnel isn't carrying your traffic, so your real IP address is exposed.",
                "Disconnect and reconnect Proton. If it persists, check the kill switch setting in the Proton app.")
    if ts.get("exit_node") and px.get("connected"):
        add("attention", "A Tailscale exit node is on while Proton is connected",
            "Tailscale's exit node and another full-tunnel VPN fight over all traffic; only one can win.",
            "Use one at a time: tailscale set --exit-node= to turn the exit node off.")
    if net.get("cgnat_overlap"):
        add("attention", "Another network interface uses Tailscale's address range (100.64.0.0/10)",
            "Interfaces: " + ", ".join(net["cgnat_overlap"]),
            "Two networks claiming the same addresses breaks routing. Change the other network's range, or see Tailscale's "
            "'CGNAT conflicts' troubleshooting page.")

    # DNS
    owner = net.get("dns_owner", "")
    if px.get("connected") and owner:
        if owner == px["device"] or owner.startswith(("proton", "wg", "tun", "pvpn")):
            add("ok", f"DNS lookups go through Proton ({owner})")
        elif owner.startswith("tailscale"):
            add("attention", "DNS lookups are being handled by Tailscale, not Proton",
                "That happens when Tailscale is set to override DNS (or uses an exit node), and it can reveal the sites you visit "
                "to a resolver outside the Proton tunnel.", "In Tailscale's admin console, check the DNS and exit-node settings.")
        else:
            add("attention", f"Possible DNS leak: lookups are going out through '{owner}', not Proton",
                "Your internet provider or network could see which sites you look up even though the traffic is tunnelled.",
                "In the Proton app, turn on its DNS/kill switch protections and reconnect. Then re-run this check.")

    # IPv6
    if px.get("connected") and net.get("ipv6_default_dev") and not (net["ipv6_default_dev"] == px["device"] or net["ipv6_default_dev"].startswith(("proton", "wg", "tun", "pvpn", "ipv6leak"))):
        add("attention", "IPv6 traffic may bypass the VPN",
            f"IPv6 internet traffic leaves through '{net['ipv6_default_dev']}'.",
            "Turn on IPv6 leak protection in the Proton app, or disable IPv6 for your Wi-Fi connection.")
    return out


def collect(do_public_ip: bool = False, do_ping: bool = False) -> dict:
    ts = tailscale_status()
    px = proton_status()
    rc, routes = _run(["ip", "route", "show", "default"])
    rc6, routes6 = _run(["ip", "-6", "route", "show", "default"])
    d4, d6 = parse_default_routes(routes), parse_default_routes(routes6)
    rc, dns = _run(["resolvectl", "status"])
    net = {
        "internet_route_dev": route_dev("1.1.1.1") or (d4[0]["dev"] if d4 else ""),
        "tailscale_route_dev": route_dev(TAILSCALE_DNS_IP) if ts.get("state") == "Running" else "",
        "ipv6_default_dev": d6[0]["dev"] if d6 else "",
        "dns_owner": dns_owner(parse_resolvectl(dns)) if rc == 0 else "",
        "cgnat_overlap": cgnat_overlaps(interface_addrs()),
    }
    result = {"tailscale": ts, "proton": px, "network": net, "findings": analyse(ts, px, net)}
    if do_ping:
        peer = (ts.get("peer_ips_online") or [""])[0]
        result["tailscale_ping"] = tailscale_ping(peer)
        if peer and not result["tailscale_ping"]["ok"] and px.get("connected"):
            result["findings"].append({"level": "attention", "title": "Couldn't reach a Tailscale device while Proton is connected",
                                       "detail": result["tailscale_ping"]["detail"],
                                       "advice": "Proton's kill switch may be blocking Tailscale. Allow Tailscale in Proton, or test with Proton off."})
    if do_public_ip:
        result["public_ip"] = public_ip()
    return result


def render_text(r: dict) -> str:
    sym = {"ok": "ok  ", "attention": "FIX ", "info": "info"}
    lines = []
    for f in r["findings"]:
        lines.append(f"[{sym[f['level']]}] {f['title']}")
        if f.get("detail"):
            lines.append(f"       {f['detail']}")
        if f.get("advice") and f["level"] == "attention":
            lines.append(f"       -> {f['advice']}")
    if "public_ip" in r:
        p = r["public_ip"]
        lines.append(f"Public address: {p.get('ip') or p.get('error')}" + (f" ({p['loc']})" if p.get("loc") else ""))
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--text", action="store_true")
    ap.add_argument("--public-ip", action="store_true")
    ap.add_argument("--tailscale-ping", action="store_true")
    a = ap.parse_args()
    r = collect(a.public_ip, a.tailscale_ping)
    print(json.dumps(r) if a.json else render_text(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())

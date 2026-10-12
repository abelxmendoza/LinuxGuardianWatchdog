"""VPN diagnostics for Tailscale + Proton: parsers on realistic output, and a verdict for each way they can go wrong."""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import vpn_status as vs  # noqa: E402

TS_JSON = json.dumps({
    "BackendState": "Running", "Health": [], "MagicDNSSuffix": "x.ts.net", "CurrentTailnet": {"Name": "me@example.com"},
    "TailscaleIPs": ["100.67.88.80"], "Self": {"Online": True},
    "Peer": {"a": {"Online": True, "TailscaleIPs": ["100.1.1.1"]}, "b": {"Online": False, "TailscaleIPs": ["100.1.1.2"]}},
})

RESOLVECTL = """\
Global
       Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported

Link 2 (wlp129s0)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: 192.168.1.1
       DNS Servers: 192.168.1.1

Link 3 (tailscale0)
    Current Scopes: DNS
         Protocols: -DefaultRoute -LLMNR
       DNS Servers: 100.100.100.100 fd7a:115c:a1e0::53
        DNS Domain: hartley-ghost.ts.net ~0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa
                    ~100.100.in-addr.arpa ~101.100.in-addr.arpa
"""

NM = "Home Wi-Fi:aaaa:802-11-wireless:wlp1\nProtonVPN US-CA#5:bbbb:wireguard:proton0\npvpn-killswitch:cccc:dummy:pvpn0\npvpn-ipv6leak-protection:dddd:dummy:ipv6leakintrf0\nOld Cafe:eeee:802-11-wireless:\n"


# ------------------------------------------------------------------ parsers
def test_tailscale_json():
    t = vs.parse_tailscale(TS_JSON)
    assert t["state"] == "Running" and t["online"] and t["peers_total"] == 2 and t["peers_online"] == 1
    assert t["peer_ips_online"] == ["100.1.1.1"] and not t["exit_node"] and t["tailnet"] == "me@example.com"


def test_tailscale_exit_node_and_health():
    d = json.loads(TS_JSON)
    d["ExitNodeStatus"] = {"TailscaleIPs": ["100.9.9.9/32"]}
    d["Health"] = ["DNS is not working"]
    t = vs.parse_tailscale(json.dumps(d))
    assert t["exit_node"] and t["health"] == ["DNS is not working"]


def test_garbage_tailscale_output_is_unknown_not_a_crash():
    assert vs.parse_tailscale("not json")["state"] == "unknown"


def test_nm_connections_active_means_has_a_device():
    rows = {r["name"]: r for r in vs.parse_nm_connections(NM)}
    assert rows["ProtonVPN US-CA#5"]["active"] and not rows["Old Cafe"]["active"]
    assert vs.parse_nm_connections("Name with\\: colon:uuid:vpn:tun0\n")[0]["name"] == "Name with: colon"


@pytest.mark.parametrize("name,expected", [("ProtonVPN US-CA#5", True), ("Proton VPN DE", True), ("pvpn-killswitch", True), ("Home Wi-Fi", False),
                                           ("tailscale0", False), ("MyProtonmailVPN", False)])
def test_proton_connection_names(name, expected):
    assert vs.is_proton_name(name) is expected


def test_default_routes():
    assert vs.parse_default_routes("default via 10.0.0.1 dev wlp1 proto dhcp metric 600\n") == [{"via": "10.0.0.1", "dev": "wlp1"}]
    assert vs.parse_default_routes("default dev proton0 scope link\n") == [{"via": "", "dev": "proton0"}]
    assert vs.parse_default_routes("") == []


def test_resolvectl_parsing_including_wrapped_domain_lines():
    links = vs.parse_resolvectl(RESOLVECTL)
    assert links["wlp129s0"]["servers"] == ["192.168.1.1"] and links["wlp129s0"]["default_route"]
    assert links["tailscale0"]["servers"][0] == "100.100.100.100" and "~101.100.in-addr.arpa" in links["tailscale0"]["domains"]
    assert vs.dns_owner(links) == "wlp129s0"


def test_dns_owner_prefers_the_catch_all_routing_domain():
    links = vs.parse_resolvectl(RESOLVECTL + "\nLink 4 (proton0)\n    Protocols: +DefaultRoute\n       DNS Servers: 10.2.0.1\n        DNS Domain: ~.\n")
    assert vs.dns_owner(links) == "proton0"


def test_cgnat_overlap_ignores_tailscale_itself():
    addrs = {"tailscale0": ["100.67.88.80"], "wlp1": ["192.168.1.5"], "ppp0": ["100.80.1.2"], "lo": ["127.0.0.1"]}
    assert vs.cgnat_overlaps(addrs) == ["ppp0"]


# ------------------------------------------------------------------ verdicts
TS_UP = {"installed": True, "state": "Running", "online": True, "peers_online": 3, "peers_total": 5, "tailnet": "t", "health": [], "exit_node": False}
TS_OFF = {"installed": True, "state": "Stopped"}
PX_UP = {"installed": True, "connected": True, "connection": "ProtonVPN US", "device": "proton0", "killswitch_present": True, "killswitch_names": ["pvpn-killswitch"]}
PX_DOWN = {"installed": True, "connected": False, "killswitch_present": False, "killswitch_names": []}
PX_NONE = {"installed": False, "connected": False, "killswitch_present": False, "killswitch_names": []}
NET_GOOD = {"internet_route_dev": "proton0", "tailscale_route_dev": "tailscale0", "ipv6_default_dev": "", "dns_owner": "proton0", "cgnat_overlap": []}


def levels(ts, px, net):
    return [(f["level"], f["title"]) for f in vs.analyse(ts, px, net)]


def attention(ts, px, net):
    return [f["title"] for f in vs.analyse(ts, px, net) if f["level"] == "attention"]


def test_both_healthy_has_no_warnings():
    assert attention(TS_UP, PX_UP, NET_GOOD) == []
    assert any("both up" in t for _l, t in levels(TS_UP, PX_UP, NET_GOOD))


def test_tailscale_only_is_fine():
    assert attention(TS_UP, PX_NONE, {**NET_GOOD, "internet_route_dev": "wlp1", "dns_owner": "wlp1"}) == []


def test_proton_connected_but_traffic_leaves_the_normal_way():
    bad = attention(TS_UP, PX_UP, {**NET_GOOD, "internet_route_dev": "wlp129s0"})
    assert any("leaves through 'wlp129s0'" in t for t in bad)


def test_exit_node_stacked_on_proton_is_flagged_both_ways():
    ts = {**TS_UP, "exit_node": True}
    bad = attention(ts, PX_UP, {**NET_GOOD, "internet_route_dev": "tailscale0"})
    assert any("exit node" in t.lower() for t in bad) and len(bad) >= 2


def test_tailscale_traffic_caught_by_the_other_vpn():
    bad = attention(TS_UP, PX_UP, {**NET_GOOD, "tailscale_route_dev": "proton0"})
    assert any("isn't using Tailscale" in t for t in bad)


def test_dns_leak_is_only_judged_when_proton_is_connected():
    leaky = {**NET_GOOD, "dns_owner": "wlp129s0"}
    assert any("DNS leak" in t for t in attention(TS_UP, PX_UP, leaky))
    assert not any("DNS" in t for t in attention(TS_UP, PX_DOWN, leaky))


def test_dns_handled_by_tailscale_while_proton_is_up():
    assert any("handled by Tailscale" in t for t in attention(TS_UP, PX_UP, {**NET_GOOD, "dns_owner": "tailscale0"}))


def test_ipv6_bypass():
    assert any("IPv6" in t for t in attention(TS_UP, PX_UP, {**NET_GOOD, "ipv6_default_dev": "wlp129s0"}))
    assert not any("IPv6" in t for t in attention(TS_UP, PX_UP, {**NET_GOOD, "ipv6_default_dev": "ipv6leakintrf0"}))


def test_killswitch_left_armed_while_disconnected():
    px = {**PX_DOWN, "killswitch_present": True, "killswitch_names": ["pvpn-killswitch"]}
    bad = attention(TS_UP, px, {**NET_GOOD, "internet_route_dev": "wlp1"})
    assert any("kill switch is armed" in t for t in bad)


def test_cgnat_conflict():
    assert any("100.64.0.0/10" in t for t in attention(TS_UP, PX_UP, {**NET_GOOD, "cgnat_overlap": ["ppp0"]}))


def test_tailscale_states_get_a_plain_next_step():
    for state, word in (("NeedsLogin", "sign in"), ("Stopped", "turned off")):
        f = [x for x in vs.analyse({"installed": True, "state": state}, PX_NONE, NET_GOOD) if x["level"] == "attention"][0]
        assert word in f["title"] and "tailscale up" in f["advice"]


def test_tailscale_health_warnings_are_surfaced():
    assert any("reports a problem" in t for t in attention({**TS_UP, "health": ["No DNS"]}, PX_NONE, NET_GOOD))


def test_every_attention_finding_says_what_to_do():
    scenarios = [(TS_OFF, PX_UP, {**NET_GOOD, "internet_route_dev": "wlp1", "dns_owner": "wlp1", "cgnat_overlap": ["ppp0"], "ipv6_default_dev": "wlp1"}),
                 ({**TS_UP, "exit_node": True}, PX_UP, {**NET_GOOD, "internet_route_dev": "tailscale0"})]
    for ts, px, net in scenarios:
        for f in vs.analyse(ts, px, net):
            if f["level"] == "attention" and "reports a problem" not in f["title"]:
                assert f["advice"], f["title"]


# ----------------------------------------------------------- end to end with stub commands
def stub(bindir: Path, name: str, body: str) -> None:
    p = bindir / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


def test_collect_with_stub_commands(tmp_path, monkeypatch):
    b = tmp_path / "bin"
    b.mkdir()
    ts_file = tmp_path / "ts.json"
    ts_file.write_text(TS_JSON)
    stub(b, "tailscale", f'[ "$1" = "status" ] && cat "{ts_file}"; [ "$1" = "ping" ] && echo "pong from x" ; exit 0')
    stub(b, "nmcli", f"printf '%s' '{NM}'")
    stub(b, "dpkg-query", "printf 'proton-vpn-gnome-desktop\\tinstall ok installed\\n'")
    stub(b, "resolvectl", f"cat <<'EOF'\n{RESOLVECTL}\nEOF")
    stub(b, "ip", '''case "$*" in
  "route show default") echo "default via 10.0.0.1 dev wlp129s0" ;;
  "-6 route show default") ;;
  "route get 1.1.1.1") echo "1.1.1.1 via 10.0.0.1 dev wlp129s0 src 10.0.0.5" ;;
  "route get 100.100.100.100") echo "100.100.100.100 dev tailscale0 src 100.67.88.80" ;;
  "-o addr show") echo "2: wlp129s0    inet 10.0.0.5/24 brd x scope global wlp129s0" ;;
esac''')
    monkeypatch.setenv("PATH", f"{b}:{os.environ['PATH']}")
    r = vs.collect(do_ping=True)
    assert r["proton"]["connected"] and r["proton"]["device"] == "proton0" and r["proton"]["packages"] == ["proton-vpn-gnome-desktop"]
    assert r["proton"]["killswitch_present"] and r["tailscale"]["peers_online"] == 1
    assert r["network"]["internet_route_dev"] == "wlp129s0"
    titles = [f["title"] for f in r["findings"] if f["level"] == "attention"]
    assert any("leaves through 'wlp129s0'" in t for t in titles) and any("DNS leak" in t for t in titles)
    assert r["tailscale_ping"]["ok"]
    assert "FIX" in vs.render_text(r)


def test_missing_tools_do_not_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    r = vs.collect()
    assert r["tailscale"]["installed"] is False and r["proton"]["installed"] is False
    assert vs.render_text(r)


def test_public_ip_check_is_never_part_of_the_default_collect(monkeypatch):
    called = []
    monkeypatch.setattr(vs, "public_ip", lambda: called.append(1) or {"ip": "x"})
    monkeypatch.setattr(vs, "_run", lambda *a, **k: (127, ""))
    monkeypatch.setattr(vs.shutil, "which", lambda n: None)
    vs.collect()
    assert not called
    vs.collect(do_public_ip=True)
    assert called


def test_tailscale_ping_refuses_odd_input():
    assert vs.tailscale_ping("1.2.3.4; reboot")["ok"] is False


def test_proton_tunnel_is_found_from_the_network_interface_even_if_networkmanager_does_not_list_it(tmp_path, monkeypatch):
    b = tmp_path / "bin"
    b.mkdir()
    stub(b, "nmcli", "exit 0")
    stub(b, "dpkg-query", "exit 1")
    stub(b, "ip", 'echo "7: proton0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT"')
    monkeypatch.setenv("PATH", f"{b}:{os.environ['PATH']}")
    px = vs.proton_status()
    assert px["installed"] and px["connected"] and px["device"] == "proton0"


def test_a_down_proton_interface_is_not_called_connected(tmp_path, monkeypatch):
    b = tmp_path / "bin"
    b.mkdir()
    stub(b, "nmcli", "exit 0")
    stub(b, "dpkg-query", "exit 1")
    stub(b, "ip", 'echo "7: proton0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN"')
    monkeypatch.setenv("PATH", f"{b}:{os.environ['PATH']}")
    px = vs.proton_status()
    assert px["installed"] and not px["connected"]

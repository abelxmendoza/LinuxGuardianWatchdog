"""The Exposure page's outside-in picture: link, address, port, program, stays."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from linuxguardian_ui.exposure_stack import exposure_stack  # noqa: E402

WIFI = {"iface": "wlp1", "addr": "10.200.4.228", "cidr": "10.200.0.0/20", "kind": "private"}
TAILSCALE = {"iface": "tailscale0", "addr": "100.101.2.3", "cidr": "100.101.2.3/32", "kind": "vpn"}
PUBLIC = {"iface": "eth9", "addr": "93.184.216.34", "cidr": "93.184.216.0/24", "kind": "public"}

META = {
    "networks": [WIFI, TAILSCALE],
    "internet_dev": "wlp1",
    "firewall": {"state": "active", "kind": "ufw", "coverage": "default_deny"},
}


def service(**overrides) -> dict:
    row = {
        "id": "tcp:5900:vino-server",
        "proto": "tcp",
        "port": 5900,
        "label": "VNC remote desktop",
        "severity": "warning",
        "scope": "all",
        "process": "vino-server",
        "friendly": "Screen sharing",
        "owner_known": True,
        "peers": ["10.0.0.9"],
        "reasons": ["Listening on ALL network interfaces, so anything on wlp1 (10.200.0.0/20) can try to connect."],
        "reachable_via": [WIFI, TAILSCALE],
    }
    row.update(overrides)
    return row


def loopback() -> dict:
    return service(
        id="tcp:25:master", port=25, proto="tcp", label="Mail", severity="info", scope="loopback",
        process="master", friendly="Mail", reachable_via=[], peers=[], reasons=["Only reachable from this laptop itself."],
    )


def routine() -> dict:
    return service(
        id="udp:7400:unknown", port=7400, proto="udp", label="ROS 2 / DDS discovery", severity="info",
        process=None, friendly=None, owner_known=False, peers=[],
        reasons=["Listening on ALL network interfaces."],
        reachable_via=[WIFI],
    )


def stack(services, meta=None, events=None):
    rungs = exposure_stack(META if meta is None else meta, services, events)
    return {rung["key"]: rung for rung in rungs}


def test_five_steps_outside_in() -> None:
    rungs = exposure_stack(META, [service(), routine(), loopback()])
    assert [rung["caption"] for rung in rungs] == ["link", "address", "port", "program", "stays"]


def test_link_names_the_path_and_who_carries_the_internet() -> None:
    link = stack([service()])["link"]
    labels = [item["label"] for item in link["items"]]
    assert labels == ["Wi-Fi (wlp1)", "Tailscale (tailscale0)"]
    assert "carries your internet" in link["items"][0]["detail"]
    assert "wlp1" in link["summary"]
    assert link["severity"] == "info"


def test_a_public_address_and_a_missing_firewall_color_the_link() -> None:
    public = stack([service()], {**META, "networks": [PUBLIC, WIFI]})["link"]
    assert public["items"][0]["severity"] == "warning"
    assert public["severity"] == "warning"
    open_fw = stack([service()], {**META, "firewall": {"state": "inactive"}})["link"]
    assert open_fw["severity"] == "critical"
    assert "No firewall" in open_fw["summary"]


def test_ports_are_the_middle_step_with_the_program_that_owns_them() -> None:
    rungs = stack([service(), routine(), loopback()])
    port = rungs["port"]
    vnc = port["items"][0]
    assert vnc["label"] == "tcp/5900  VNC remote desktop"
    assert vnc["program"] == "Screen sharing"
    assert "Connected now: 10.0.0.9" in vnc["detail"]
    assert "1 port needs attention" in port["summary"]
    assert "1 more is routine" in port["summary"]
    assert "1 port listens only on this laptop" in port["summary"]
    program = rungs["program"]
    assert program["items"] == [{"label": "Screen sharing", "detail": "tcp/5900", "severity": "warning"}]
    assert "1 other program owns routine ports" in program["summary"]
    assert "1 listener belongs to root" in program["summary"]


def test_address_lists_each_network_that_can_reach_a_listener() -> None:
    address = stack([service()])["address"]
    assert address["quiet"] is False
    assert "1 listener can be reached" in address["summary"]
    assert {item["label"] for item in address["items"]} == {
        "10.200.0.0/20 on Wi-Fi (wlp1)",
        "100.101.2.3/32 on Tailscale (tailscale0)",
    }
    assert all("VNC remote desktop" in item["detail"] for item in address["items"])


def test_loopback_only_is_quiet_below_the_link() -> None:
    rungs = stack([loopback()])
    assert rungs["address"]["quiet"] and "No listener is reachable" in rungs["address"]["summary"]
    assert rungs["port"]["quiet"] and rungs["port"]["items"] == []
    assert "1 port listens only on this laptop" in rungs["port"]["summary"]
    assert rungs["program"]["quiet"]
    assert rungs["stays"]["quiet"]


def test_an_unnamed_network_is_said_outright() -> None:
    lonely = service(reachable_via=[])
    address = stack([lonely])["address"]
    assert address["items"][0]["label"] == "A listener whose network could not be named"


def test_stays_keeps_real_persistence_and_drops_noise() -> None:
    events = [
        {"event": "new_autostart", "severity": "warning", "status": "detected", "message": "A new startup entry was modified: autostart.desktop."},
        {"event": "new_autostart", "severity": "warning", "status": "detected", "message": "A new startup entry was modified: autostart.desktop."},
        {"event": "new_usb", "severity": "info", "status": "detected", "message": "A new USB keyboard was plugged in."},
        {"event": "new_usb_composite", "severity": "warning", "status": "resolved", "message": "A USB device that acts as BOTH a keyboard and storage was plugged in."},
        {"event": "uid_zero", "severity": "critical", "status": "detected", "message": "The account 'backup' now has root privileges (uid 0)."},
    ]
    stays = stack([service()], events=events)["stays"]
    assert stays["quiet"] is False and stays["severity"] == "critical"
    assert [item["label"] for item in stays["items"]] == [
        "A new startup entry was modified: autostart.desktop.",
        "The account 'backup' now has root privileges (uid 0).",
    ]


def test_no_networks_is_a_quiet_link() -> None:
    link = stack([], {"networks": [], "internet_dev": "", "firewall": {}})["link"]
    assert link["quiet"] and "no network address" in link["summary"]

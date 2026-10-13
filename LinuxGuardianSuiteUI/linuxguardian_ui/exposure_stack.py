"""Outside-in picture of this laptop's exposure.

Display only. Every line comes from the exposure report or from a sensor event
that already exists. A quiet step means nothing there needs attention.
"""
from __future__ import annotations

SEV_RANK = {"info": 0, "warning": 1, "critical": 2}

# Sensor events that mean something would still be here after a reboot or a plug-in.
STAYS_EVENTS = frozenset({
    "new_autostart", "autostart_changed",
    "new_user", "uid_zero", "shell_enabled", "privilege_added",
    "new_usb_composite",
})


def worst(severities) -> str:
    found = "info"
    for severity in severities:
        if SEV_RANK.get(severity, 0) > SEV_RANK[found]:
            found = severity
    return found


def n_word(n: int, singular: str, plural: str | None = None) -> str:
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


def link_name(iface: str, kind: str) -> str:
    """A person's name for an interface. The interface name stays beside it."""
    if iface.startswith("tailscale"):
        return "Tailscale"
    if iface.startswith(("proton", "pvpn")):
        return "Proton VPN"
    if iface.startswith(("wl", "wlan")):
        return "Wi-Fi"
    if iface.startswith(("en", "eth")):
        return "Cable"
    if kind == "vpn" or iface.startswith(("wg", "tun", "zt")):
        return "VPN"
    if kind == "public":
        return "Public network"
    return "Local network"


def _rung(key: str, title: str, summary: str, items: list[dict], severity: str, quiet: bool) -> dict:
    return {
        "key": key, "caption": key, "title": title, "summary": summary,
        "items": items, "severity": severity, "quiet": quiet,
    }


def _quiet(key: str, title: str, summary: str) -> dict:
    return _rung(key, title, summary, [], "info", True)


def _reachable(services: list[dict]) -> list[dict]:
    return [s for s in services if s.get("scope") != "loopback"]


def _link(meta: dict) -> dict:
    nets = list(meta.get("networks") or [])
    route = meta.get("internet_dev") or ""
    fw = meta.get("firewall") or {}
    if not nets:
        return _quiet("link", "How you are connected", "This laptop has no network address up.")
    items = []
    for net in nets:
        iface = net.get("iface") or ""
        detail = f"{net.get('addr', '')} on {net.get('cidr', '')}"
        if route and iface == route:
            detail += " — carries your internet"
        items.append({
            "label": f"{link_name(iface, net.get('kind') or '')} ({iface})",
            "detail": detail,
            "severity": "warning" if net.get("kind") == "public" else "info",
        })
    bits = []
    if route and any((n.get("iface") or "") == route for n in nets):
        bits.append(f"Internet traffic leaves through {route}.")
    elif route:
        bits.append(f"Internet traffic leaves through {route}, which is not one of the addresses above.")
    else:
        bits.append("This scan could not see which interface carries your internet.")
    severity = worst(item["severity"] for item in items)
    if fw.get("state") in ("inactive", "none"):
        bits.append("No firewall is filtering these connections.")
        severity = "critical"
    return _rung("link", "How you are connected", " ".join(bits), items, severity, False)


def _address(services: list[dict]) -> dict:
    exposed = _reachable(services)
    if not exposed:
        return _quiet("address", "Who can reach a listener", "No listener is reachable from another machine.")
    groups: dict[tuple[str, str], dict] = {}
    unnamed: list[dict] = []
    for service in exposed:
        nets = service.get("reachable_via") or []
        if not nets:
            unnamed.append(service)
            continue
        for net in nets:
            key = (net.get("iface") or "", net.get("cidr") or "")
            group = groups.setdefault(key, {"severity": "info", "labels": [], "kind": net.get("kind") or ""})
            group["severity"] = worst([group["severity"], service.get("severity") or "info"])
            label = service.get("label") or "Unknown service"
            if label not in group["labels"]:
                group["labels"].append(label)
    items = []
    for (iface, cidr), group in groups.items():
        shown = ", ".join(group["labels"][:3])
        extra = len(group["labels"]) - 3
        if extra > 0:
            shown += f" and {extra} more"
        items.append({
            "label": f"{cidr} on {link_name(iface, group['kind'])} ({iface})",
            "detail": shown,
            "severity": group["severity"],
        })
    if unnamed:
        items.append({
            "label": "A listener whose network could not be named",
            "detail": ", ".join((s.get("label") or "Unknown service") for s in unnamed[:3]),
            "severity": worst(s.get("severity") or "info" for s in unnamed),
        })
    items.sort(key=lambda item: (-SEV_RANK[item["severity"]], item["label"]))
    attention = [s for s in exposed if s.get("severity") != "info"]
    if attention:
        summary = f"{n_word(len(attention), 'listener')} can be reached from another machine."
    else:
        summary = "Other machines can reach only routine listeners, such as discovery and VPN."
    return _rung("address", "Who can reach a listener", summary, items, worst(i["severity"] for i in items), False)


def _ports(services: list[dict]) -> dict:
    exposed = _reachable(services)
    local = [s for s in services if s.get("scope") == "loopback"]
    if not exposed:
        if local:
            verb = "listens" if len(local) == 1 else "listen"
            summary = (
                f"{n_word(len(local), 'port')} {verb} only on this laptop. "
                "Other machines cannot connect to them."
            )
        else:
            summary = "Nothing is listening."
        return _quiet("port", "What is listening", summary)
    items = []
    for service in exposed:
        reason = (service.get("reasons") or [""])[0]
        peers = service.get("peers") or []
        if peers:
            reason = f"{reason} Connected now: {', '.join(peers)}".strip()
        items.append({
            "id": service.get("id"),
            "label": f"{service.get('proto')}/{service.get('port')}  {service.get('label')}",
            "detail": reason,
            "severity": service.get("severity") or "info",
            "program": service.get("friendly") or service.get("process") or "owner not visible",
        })
    attention = [item for item in items if item["severity"] != "info"]
    routine = len(items) - len(attention)
    bits = []
    if attention:
        verb = "needs" if len(attention) == 1 else "need"
        bits.append(f"{n_word(len(attention), 'port')} {verb} attention.")
    else:
        bits.append("No listening port needs attention.")
    if routine:
        verb = "is" if routine == 1 else "are"
        bits.append(f"{routine} more {verb} routine.")
    if local:
        verb = "listens" if len(local) == 1 else "listen"
        bits.append(f"{n_word(len(local), 'port')} {verb} only on this laptop.")
    return _rung("port", "What is listening", " ".join(bits), items, worst(i["severity"] for i in items), False)


def _programs(services: list[dict]) -> dict:
    exposed = _reachable(services)
    if not exposed:
        return _quiet("program", "Which program owns a port", "No program is offering a port to another machine.")
    groups: dict[str, dict] = {}
    for service in exposed:
        name = service.get("friendly") or service.get("process") or "Owner not visible"
        group = groups.setdefault(name, {"severity": "info", "ports": []})
        group["severity"] = worst([group["severity"], service.get("severity") or "info"])
        port = f"{service.get('proto')}/{service.get('port')}"
        if port not in group["ports"]:
            group["ports"].append(port)
    items = []
    routine = 0
    for name, group in groups.items():
        if group["severity"] == "info":
            routine += 1
            continue
        items.append({"label": name, "detail": ", ".join(group["ports"]), "severity": group["severity"]})
    items.sort(key=lambda item: (-SEV_RANK[item["severity"]], item["label"]))
    if items:
        verb = "owns" if len(items) == 1 else "own"
        summary = f"{n_word(len(items), 'program')} {verb} a port that needs attention."
    else:
        summary = "No program owns a port that needs attention."
    if routine:
        verb = "owns" if routine == 1 else "own"
        summary += f" {n_word(routine, 'other program')} {verb} routine ports."
    hidden = sum(1 for service in exposed if not service.get("owner_known"))
    if hidden:
        verb = "belongs" if hidden == 1 else "belong"
        summary += (
            f" {n_word(hidden, 'listener')} {verb} to root or another user, so their program can't be named."
        )
    severity = worst(item["severity"] for item in items) if items else "info"
    return _rung("program", "Which program owns a port", summary, items, severity, not items)


def _stays(events: list[dict]) -> dict:
    seen: set[tuple[str, str]] = set()
    items = []
    for event in events:
        name = event.get("event")
        if name not in STAYS_EVENTS or event.get("status") == "resolved":
            continue
        severity = event.get("severity") or "info"
        if severity not in ("warning", "critical"):
            continue
        message = str(event.get("message") or "").strip()
        if not message or (name, message) in seen:
            continue
        seen.add((name, message))
        items.append({"label": message, "detail": "", "severity": severity})
        if len(items) >= 6:
            break
    if not items:
        return _quiet(
            "stays", "What would keep something around",
            "No new startup entry, account, or USB device needs attention.",
        )
    return _rung(
        "stays", "What would keep something around",
        "The background checks saw something that stays after a reboot or a plug-in.",
        items, worst(item["severity"] for item in items), False,
    )


def exposure_stack(meta: dict, services: list[dict], events: list[dict] | None = None) -> list[dict]:
    """Five steps, outside in: link, address, port, program, stays."""
    return [
        _link(meta or {}),
        _address(services or []),
        _ports(services or []),
        _programs(services or []),
        _stays(events or []),
    ]

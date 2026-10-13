#!/usr/bin/env python3
"""Inventory running processes as grouped, plain-English records (JSON lines).

Used by linux_process_manager.sh --list. Adds group, impact, origin, systemd
unit, parent, and listening ports so the GUI is not a raw `ps` dump.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

UI_DIR = Path(__file__).resolve().parents[1] / "LinuxGuardianSuiteUI"
if str(UI_DIR) not in sys.path:
    sys.path.insert(0, str(UI_DIR))

from linuxguardian_ui.process_catalog import (  # noqa: E402
    KNOWN_APPS,
    explain,
    is_ros_cmdline,
)

# First match wins. Specific app/stack groups before generic buckets.
GROUP_DEFS: list[dict] = [
    {
        "id": "gnome-desktop",
        "title": "GNOME Desktop",
        "blurb": "Your desktop, windows, and graphical session.",
        "impact": "session_critical",
        "comms": {
            "gnome-shell",
            "Xorg",
            "Xwayland",
            "mutter",
            "gnome-session-binary",
            "gnome-session-ctl",
            "gnome-session-b",
            "gjs",
        },
        "prefixes": ("gnome-session-",),
    },
    {
        "id": "gnome-settings",
        "title": "GNOME Settings",
        "blurb": "Keyboard, power, sound, display, accessibility.",
        "impact": "desktop_affected",
        "prefixes": ("gsd-",),
        "comms": {"dconf-service", "colord"},
    },
    {
        "id": "gnome-files",
        "title": "GNOME Files & Devices",
        "blurb": "USB drives, Trash, phones, cameras, mounted filesystems.",
        "impact": "desktop_affected",
        "prefixes": ("gvfs", "tracker-miner"),
        "comms": {"gvfsd", "gvfsd-fuse", "gvfsd-trash"},
    },
    {
        "id": "accounts",
        "title": "Accounts & Credentials",
        "blurb": "Password keyring and online accounts.",
        "impact": "desktop_affected",
        "comms": {"goa-daemon", "goa-identity-se", "gnome-keyring-d", "gnome-keyring-daemon", "gcr-prompter"},
        "prefixes": ("gnome-keyring",),
    },
    {
        "id": "input",
        "title": "Keyboard & Input",
        "blurb": "Keyboard layout and input-method services.",
        "impact": "desktop_affected",
        "prefixes": ("ibus-", "at-spi"),
        "comms": {"ibus-daemon", "at-spi-bus-laun", "at-spi2-registr"},
    },
    {
        "id": "calendar",
        "title": "Calendar & Contacts",
        "blurb": "GNOME/Evolution calendar and address-book backends.",
        "impact": "feature_stops",
        "prefixes": ("evolution-", "gnome-shell-cal"),
    },
    {
        "id": "portals",
        "title": "App permissions & dialogs",
        "blurb": "File pickers, screenshots, screen sharing, sandbox permissions.",
        "impact": "desktop_affected",
        "prefixes": ("xdg-desktop-portal", "xdg-desktop-por", "xdg-document-portal", "xdg-document-po", "xdg-permission"),
    },
    {
        "id": "session-bus",
        "title": "Session bus",
        "blurb": "D-Bus — how apps and the desktop talk to each other.",
        "impact": "session_critical",
        "comms": {"dbus-daemon", "dbus-broker"},
    },
    {
        "id": "audio",
        "title": "Audio",
        "blurb": "Sound and screen-sharing media.",
        "impact": "session_critical",
        "comms": {"pipewire", "pulseaudio", "wireplumber", "pipewire-pulse", "rtkit-daemon", "pipewire-media-"},
        "prefixes": ("pipewire",),
    },
    {
        "id": "networking",
        "title": "Networking",
        "blurb": "Wi-Fi, DNS, VPN.",
        "impact": "session_critical",
        "comms": {
            "NetworkManager",
            "wpa_supplicant",
            "systemd-resolve",
            "systemd-network",
            "tailscaled",
            "dnsmasq",
            "networkd-dispat",
        },
        "prefixes": ("networkd-dispat",),
    },
    {
        "id": "docker",
        "title": "Docker",
        "blurb": "Containers and the Docker engine.",
        "impact": "feature_stops",
        "comms": {"dockerd", "containerd", "docker-proxy"},
        "prefixes": ("containerd-shim",),
    },
    {
        "id": "ros2",
        "title": "ROS 2 / Robotics",
        "blurb": "Your robotics nodes and topic tools.",
        "impact": "feature_stops",
        "cmdline_any": ("/opt/ros/", "ros2", "rclpy", "rclcpp", "topic_tools", "ament_"),
        "comms": {"mux", "rviz2", "gazebo", "gz"},
    },
    {
        "id": "mail",
        "title": "Mail (Postfix)",
        "blurb": "Local mail server. Only needed if this machine sends email.",
        "impact": "feature_stops",
        "comms": {"master", "qmgr", "pickup", "smtp", "smtpd"},
        "exe_contains": ("postfix",),
    },
    {
        "id": "remote-desktop",
        "title": "Remote desktop",
        "blurb": "VNC / GNOME remote control. Verify this is intentional.",
        "impact": "feature_stops",
        "comms": {"vino-server"},
    },
    {
        "id": "gpu",
        "title": "GPU",
        "blurb": "NVIDIA driver helpers.",
        "impact": "desktop_affected",
        "prefixes": ("nvidia-persiste", "nvidia-persist", "switcheroo"),
        "comms": {"switcheroo-cont"},
    },
    {
        "id": "logging",
        "title": "Logging",
        "blurb": "System and journal logs.",
        "impact": "desktop_affected",
        "comms": {"systemd-journald", "systemd-journal", "rsyslogd", "syslogd", "journalctl", "kerneloops"},
        "prefixes": ("systemd-journal",),
        "units": ("systemd-journald.service", "rsyslog.service"),
    },
    {
        "id": "hardware",
        "title": "Hardware & Devices",
        "blurb": "Device detection, USB, Thunderbolt, ACPI.",
        "impact": "desktop_affected",
        "comms": {"systemd-udevd", "systemd-udev", "boltd", "acpid", "irqbalance"},
        "prefixes": ("systemd-udev",),
        "units": ("systemd-udevd.service", "bolt.service", "acpid.service"),
    },
    {
        "id": "memory",
        "title": "Memory Management",
        "blurb": "Out-of-memory handling.",
        "impact": "session_critical",
        "comms": {"systemd-oomd", "systemd-oom"},
        "prefixes": ("systemd-oom",),
        "units": ("systemd-oomd.service",),
    },
    {
        "id": "time",
        "title": "Time & Clock",
        "blurb": "Keeps the system clock in sync.",
        "impact": "desktop_affected",
        "comms": {"systemd-timesyncd", "systemd-timesyn", "chronyd", "ntpd", "ntp"},
        "prefixes": ("systemd-timesyn",),
        "units": ("systemd-timesyncd.service", "chrony.service"),
    },
    {
        "id": "scheduled",
        "title": "Scheduled Tasks",
        "blurb": "cron and at — timers for scheduled jobs.",
        "impact": "feature_stops",
        "comms": {"cron", "crond", "atd", "anacron"},
        "units": ("cron.service", "atd.service"),
    },
    {
        "id": "power",
        "title": "Power",
        "blurb": "Battery, sleep, and power profiles.",
        "impact": "desktop_affected",
        "comms": {"upowerd", "power-profiles-daemon", "power-profiles-", "thermald"},
        "prefixes": ("power-profiles", "upower"),
        "units": ("upower.service", "power-profiles-daemon.service"),
    },
    {
        "id": "packages",
        "title": "Package Management & Updates",
        "blurb": "Snaps, apt, and unattended upgrades.",
        "impact": "feature_stops",
        "comms": {
            "snapd",
            "packagekitd",
            "unattended-upgrades",
            "unattended-upgr",
            "packagekit",
            "snap-store",
            "snapd-desktop-i",
            "fwupd",
            "update-notifier",
        },
        "prefixes": ("unattended-upgr", "packagekit", "snapd-desktop", "fwupd"),
        "units": ("snapd.service", "unattended-upgrades.service", "packagekit.service"),
    },
    {
        "id": "login",
        "title": "Login & Sessions",
        "blurb": "Login screen and session tracking.",
        "impact": "session_critical",
        "comms": {
            "systemd-logind",
            "systemd-login",
            "gdm",
            "gdm3",
            "gdm-session-wor",
            "accounts-daemon",
            "(sd-pam)",
            "user-session-he",
        },
        "prefixes": ("gdm-", "systemd-login"),
        "units": ("systemd-logind.service", "gdm.service", "accounts-daemon.service"),
    },
    {
        "id": "storage",
        "title": "Storage & Devices",
        "blurb": "Disks, automount, block maps.",
        "impact": "desktop_affected",
        "comms": {"udisksd", "blkmapd", "udisks2"},
        "units": ("udisks2.service",),
    },
    {
        "id": "permissions",
        "title": "Permissions & Security",
        "blurb": "Privilege prompts (polkit) and policy.",
        "impact": "session_critical",
        "comms": {"polkitd", "polkit-agent-he", "polkit-gnome-au"},
        "prefixes": ("polkit",),
        "units": ("polkit.service",),
    },
    {
        "id": "printing",
        "title": "Printing",
        "blurb": "CUPS print spooler and printer discovery.",
        "impact": "feature_stops",
        "comms": {"cupsd", "cups-browsed", "run-cups-browse"},
        "prefixes": ("cups", "run-cups"),
        "units": ("cups.service", "cups-browsed.service"),
        "exe_contains": ("cups",),
    },
    {
        "id": "systemd-pid1",
        "title": "System core",
        "blurb": "PID 1 systemd — the machine service manager.",
        "impact": "session_critical",
        "special": "systemd-pid1",
    },
    {
        "id": "systemd-user",
        "title": "User session manager",
        "blurb": "systemd --user for this login.",
        "impact": "session_critical",
        "special": "systemd-user",
    },
]

IMPACT_LABELS = {
    "close_app": "Close app",
    "feature_stops": "Feature stops",
    "desktop_affected": "Desktop affected",
    "session_critical": "Don't kill",
    "unknown": "Unknown",
}

IMPACT_IF_STOPPED = {
    "close_app": "That application closes. The rest of the desktop stays up.",
    "feature_stops": "A feature stops (printer, calendar, containers, ROS, remote desktop). The desktop should stay up.",
    "desktop_affected": "Desktop helpers may break (files, settings, portals, typing).",
    "session_critical": "Your session or the machine can freeze, log you out, or lose the network.",
    "unknown": "LinuxGuardian does not have enough evidence. Do not assume it is safe.",
}

APP_COMM_TO_GROUP = {
    "firefox": ("firefox", "Firefox", "Browser plus tabs and helpers."),
    "firefox-esr": ("firefox", "Firefox", "Browser plus tabs and helpers."),
    "Isolated Web Co": ("firefox", "Firefox", "Browser plus tabs and helpers."),
    "Web Content": ("firefox", "Firefox", "Browser plus tabs and helpers."),
    "Privileged Cont": ("firefox", "Firefox", "Browser plus tabs and helpers."),
    "Socket Process": ("firefox", "Firefox", "Browser plus tabs and helpers."),
    "RDD Process": ("firefox", "Firefox", "Browser plus tabs and helpers."),
    "WebExtensions": ("firefox", "Firefox", "Browser plus tabs and helpers."),
    "Utility Process": ("firefox", "Firefox", "Browser plus tabs and helpers."),
    "chrome_crashpad": ("firefox", "Firefox", "Browser plus tabs and helpers."),
    "chrome": ("chrome", "Google Chrome", "Browser plus tabs and helpers."),
    "chromium": ("chromium", "Chromium", "Browser plus tabs and helpers."),
    "cursor": ("cursor", "Cursor", "Editor plus extensions and helpers."),
    "cursorsandbox": ("cursor", "Cursor", "Editor plus extensions and helpers."),
    "code": ("vscode", "VS Code", "Editor plus helpers."),
    "code-oss": ("vscode", "VS Code", "Editor plus helpers."),
    "gnome-terminal-server": ("terminal", "Terminal", "GNOME terminal windows."),
    "gnome-terminal-": ("terminal", "Terminal", "GNOME terminal windows."),
    "nautilus": ("files", "Files", "GNOME file manager windows."),
    "grok": ("grok", "Grok", "xAI Grok desktop / TUI."),
}


def _cmdline(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except OSError:
        return ""


def _exe(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def _comm(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/comm").read_text().strip()
    except OSError:
        return ""


def _cgroup_unit(pid: int) -> str:
    try:
        text = Path(f"/proc/{pid}/cgroup").read_text()
    except OSError:
        return ""
    match = re.findall(r"([^/\s]+\.(?:service|scope|slice|socket))", text)
    return match[-1] if match else ""


def _origin(exe: str, cmdline: str) -> str:
    blob = f"{exe} {cmdline}"
    if "/snap/" in blob:
        return "Snap"
    if "/opt/ros/" in blob or "ros2" in blob:
        return "ROS 2"
    if "tailscale" in blob:
        return "Tailscale"
    if "postfix" in blob:
        return "Postfix (Ubuntu)"
    if "/usr/libexec/gsd-" in exe or "/usr/lib/gnome" in exe or "/usr/libexec/gvfs" in exe:
        return "Ubuntu/GNOME"
    if "/usr/lib/xorg" in exe or exe.endswith("/Xorg"):
        return "Ubuntu/Xorg"
    if "/usr/libexec/vino" in exe:
        return "Ubuntu/GNOME (remote desktop)"
    if exe.startswith("/usr/") or exe.startswith("/bin/") or exe.startswith("/sbin/"):
        return "Ubuntu package"
    if exe.startswith("/home/"):
        return "User-installed"
    return "Unknown"


def _load_listening() -> dict[str, str]:
    """socket inode -> 'tcp:22' / 'tcp6:8080'."""
    mapping: dict[str, str] = {}
    for name, proto in (("tcp", "tcp"), ("tcp6", "tcp6"), ("udp", "udp"), ("udp6", "udp6")):
        path = Path(f"/proc/net/{name}")
        if not path.is_file():
            continue
        try:
            lines = path.read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10:
                continue
            if proto.startswith("tcp") and fields[3] != "0A":
                continue
            local = fields[1]
            inode = fields[9]
            if inode == "0":
                continue
            try:
                port = int(local.rsplit(":", 1)[1], 16)
            except ValueError:
                continue
            mapping[inode] = f"{proto}:{port}"
    return mapping


def _pid_listening(pid: int, inode_ports: dict[str, str]) -> list[str]:
    if not inode_ports:
        return []
    fd_dir = Path(f"/proc/{pid}/fd")
    found: list[str] = []
    try:
        for fd in fd_dir.iterdir():
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                inode = target[8:-1]
                port = inode_ports.get(inode)
                if port and port not in found:
                    found.append(port)
    except OSError:
        return []
    return found


def _assign_group(
    comm: str, pid: int, cmdline: str, exe: str, unit: str = ""
) -> tuple[str, str, str, str]:
    """Return group_id, title, blurb, impact.

    Unknown is never returned as close_app. Match comm, prefixes, cmdline,
    executable path, and systemd unit.
    """
    if comm == "systemd" and pid == 1:
        return ("systemd-pid1", "System core", "PID 1 systemd — the machine service manager.", "session_critical")
    if comm == "systemd" and pid != 1:
        return ("systemd-user", "User session manager", "systemd --user for this login.", "session_critical")

    blob = f"{cmdline} {exe}"
    unit_l = (unit or "").lower()
    for spec in GROUP_DEFS:
        if spec.get("special") in {"systemd-pid1", "systemd-user"}:
            continue
        if comm in spec.get("comms", set()):
            return spec["id"], spec["title"], spec["blurb"], spec["impact"]
        for prefix in spec.get("prefixes", ()):
            if comm.startswith(prefix) or comm.lower().startswith(prefix):
                return spec["id"], spec["title"], spec["blurb"], spec["impact"]
        for token in spec.get("cmdline_any", ()):
            if token.lower() in blob.lower():
                return spec["id"], spec["title"], spec["blurb"], spec["impact"]
        for token in spec.get("exe_contains", ()):
            if token in exe or token in cmdline:
                return spec["id"], spec["title"], spec["blurb"], spec["impact"]
        for token in spec.get("units", ()):
            if token.lower() in unit_l:
                return spec["id"], spec["title"], spec["blurb"], spec["impact"]

    blob_l = blob.lower()
    if "linuxguardian" in blob_l:
        return ("linuxguardian", "LinuxGuardian", "This watchdog app.", "close_app")

    if comm in APP_COMM_TO_GROUP:
        gid, title, blurb = APP_COMM_TO_GROUP[comm]
        return gid, title, blurb, "close_app"
    if comm in KNOWN_APPS:
        title, blurb = KNOWN_APPS[comm]
        return f"app-{comm}", title, blurb, "close_app"

    if is_ros_cmdline(cmdline, exe):
        return (
            "ros2",
            "ROS 2 / Robotics",
            "Your robotics nodes and topic tools.",
            "feature_stops",
        )

    return ("unknown", "Unknown", "LinuxGuardian does not recognize this yet.", "unknown")


def iter_records(sort: str = "cpu") -> list[dict]:
    inode_ports = _load_listening()
    rows: list[dict] = []
    child_of: dict[int, int] = defaultdict(int)

    pids: list[int] = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            pids.append(int(entry.name))

    stats: dict[int, dict] = {}
    for pid in pids:
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
        except OSError:
            continue
        try:
            tail = stat.rsplit(")", 1)[1].split()
            ppid = int(tail[1])
        except (IndexError, ValueError):
            continue
        child_of[ppid] += 1
        # comm from stat is inside parentheses; prefer /proc/pid/comm
        stats[pid] = {"ppid": ppid}

    # cpu/mem from a single ps pass (etimes too)
    ps_map: dict[int, tuple[float, float, str, str]] = {}
    import subprocess

    proc = subprocess.run(
        ["ps", "-eo", "pid,%cpu,%mem,etimes,user", "--no-headers"],
        capture_output=True,
        text=True,
    )
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            pid = int(parts[0])
            cpu = float(parts[1])
            mem = float(parts[2])
        except ValueError:
            continue
        ps_map[pid] = (cpu, mem, parts[3], parts[4])

    for pid, meta in stats.items():
        comm = _comm(pid)
        if not comm:
            continue
        cmdline = _cmdline(pid)
        exe = _exe(pid)
        unit = _cgroup_unit(pid)
        cpu, mem, etimes, user = ps_map.get(pid, (0.0, 0.0, "0", ""))
        kind = "kernel" if not cmdline else "system"
        gid, gtitle, gblurb, impact = _assign_group(comm, pid, cmdline, exe, unit)
        if not cmdline:
            gid, gtitle, gblurb, impact = (
                "kernel",
                "Kernel threads",
                "Linux kernel workers — not useful to end here.",
                "session_critical",
            )
            kind = "kernel"
        elif impact == "close_app":
            kind = "app"
        elif gid == "ros2":
            kind = "background"
        elif gid == "unknown" and user == os.environ.get("USER", ""):
            kind = "background"
            # stay unknown impact — never auto-promote to close_app
        name, purpose = explain(comm, kind, str(pid), cmdline, exe)
        parent_comm = _comm(meta["ppid"]) if meta["ppid"] else ""
        listening = _pid_listening(pid, inode_ports)
        if gid == "remote-desktop" and any(p.split(":")[-1] in {"5900", "5901"} for p in listening):
            ports = ", ".join(listening)
            gblurb = f"VNC is listening on {ports}. Verify you meant to allow remote control of this machine."
            purpose = f"GNOME remote desktop (Vino) accepting connections on {ports}."
        if_stopped = IMPACT_IF_STOPPED[impact]
        rec = {
            "pid": pid,
            "ppid": meta["ppid"],
            "cpu": cpu,
            "mem": mem,
            "etimes": etimes,
            "user": user,
            "comm": comm,
            "exe": exe,
            "cmdline": cmdline,
            "kind": kind,
            "impact": impact,
            "impact_label": IMPACT_LABELS[impact],
            "group_id": gid,
            "group_title": gtitle,
            "group_blurb": gblurb,
            "name": name,
            "purpose": purpose,
            "recommendation": "Leave running" if impact != "close_app" else "Safe to close the app",
            "if_stopped": if_stopped,
            "origin": _origin(exe, cmdline),
            "unit": unit,
            "parent_comm": parent_comm,
            "listening": listening,
            "children": child_of.get(pid, 0),
        }
        if impact == "unknown":
            rec["recommendation"] = "Don't assume it's safe — inspect first"
        if impact == "session_critical":
            rec["recommendation"] = "Don't kill"
        rows.append(rec)

    key = "mem" if sort == "mem" else "cpu"
    rows.sort(key=lambda r: r[key], reverse=True)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sort", choices=("cpu", "mem"), default="cpu")
    args = parser.parse_args()
    for rec in iter_records(sort=args.sort):
        print(json.dumps(rec, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

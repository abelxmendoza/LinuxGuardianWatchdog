"""Plain-language names/descriptions for common processes.

This is the piece that makes the process killer usable: Linux's raw process
table is full of names nobody recognizes. Rather than showing "cursorsandbox"
and "Isolated Web Co" and expecting the user to know what those are, we
translate known ones into something a person would actually understand.
Unknown processes still get a sensible fallback based on their `kind`.

Lookups can use the short `comm` name, prefixes (gsd-*, gvfs*), PID
(systemd PID 1 vs systemd --user), and the full command line (Python
scripts, ROS 2 nodes).
"""
from __future__ import annotations

from pathlib import Path

# comm -> (friendly name, one-line description)
KNOWN_APPS: dict[str, tuple[str, str]] = {
    "firefox": ("Firefox", "Web browser"),
    "firefox-esr": ("Firefox", "Web browser"),
    "chrome": ("Google Chrome", "Web browser (one of several processes Chrome runs per tab/feature)"),
    "chromium": ("Chromium", "Web browser"),
    "Isolated Web Co": ("Browser tab", "A sandboxed process for one browser tab or site"),
    "cursor": ("Cursor", "Code editor"),
    "cursorsandbox": ("Cursor (helper)", "A sandboxed helper process spawned by the Cursor editor"),
    "code": ("VS Code", "Code editor"),
    "code-oss": ("VS Code", "Code editor"),
    "codium": ("VSCodium", "Code editor"),
    "claude-desktop": ("Claude", "Anthropic's Claude desktop app"),
    "claude": ("Claude", "Claude CLI/agent process"),
    "chatgpt": ("ChatGPT", "OpenAI's ChatGPT desktop app"),
    "grok": ("Grok", "xAI Grok desktop / TUI"),
    "slack": ("Slack", "Team chat app"),
    "discord": ("Discord", "Chat app"),
    "thunderbird": ("Thunderbird", "Email client"),
    "soffice.bin": ("LibreOffice", "Office suite"),
    "spotify": ("Spotify", "Music player"),
    "steam": ("Steam", "Game platform"),
    "gimp": ("GIMP", "Image editor"),
    "vlc": ("VLC", "Media player"),
    "nautilus": ("Files", "GNOME file manager"),
    "gnome-terminal-server": ("Terminal", "GNOME terminal"),
    "konsole": ("Konsole", "KDE terminal"),
    "alacritty": ("Alacritty", "Terminal emulator"),
    "kitty": ("Kitty", "Terminal emulator"),
    "gnome-text-editor": ("Text Editor", "GNOME text editor"),
    "rviz2": ("RViz", "ROS 2 3D visualization. Safe to end if you are not looking at robot data."),
    "gazebo": ("Gazebo", "Robot simulator. Safe to end if you are not running a sim."),
    "gz": ("Gazebo", "Robot simulator process."),
}

# comm (lower) -> (friendly name, description). Used for any kind.
KNOWN_SERVICES: dict[str, tuple[str, str]] = {
    "gnome-shell": (
        "GNOME Shell",
        "Your desktop shell — top bar, windows, and animations. Ending this logs you out immediately.",
    ),
    "xorg": (
        "Xorg (display server)",
        "The graphical display server. Ending this closes your entire graphical session.",
    ),
    "xwayland": (
        "XWayland",
        "Lets older X11 apps run under Wayland. Ending this may close those apps.",
    ),
    "gdm": ("GDM", "The login screen manager."),
    "gdm3": ("GDM", "The login screen manager."),
    "lightdm": ("LightDM", "A login screen manager."),
    "sddm": ("SDDM", "A login screen manager (commonly used with KDE)."),
    "networkmanager": (
        "NetworkManager",
        "Manages Wi-Fi and network connections. Ending this drops your network.",
    ),
    "systemd-journald": ("journald", "Collects and stores system logs."),
    "systemd-logind": ("logind", "Manages login sessions. Ending this can log you out."),
    "systemd-udevd": ("udevd", "Detects and configures hardware devices."),
    "dbus-daemon": (
        "D-Bus",
        "The message bus many apps and system services use to talk to each other.",
    ),
    "polkitd": ("Polkit", "Handles permission prompts for privileged actions."),
    "pulseaudio": ("PulseAudio", "The audio system. Ending this interrupts sound."),
    "pipewire": (
        "PipeWire",
        "The audio/video system. Ending this interrupts sound and screen sharing.",
    ),
    "wireplumber": ("WirePlumber", "Session manager for the audio/video system."),
    "udisksd": ("UDisks", "Handles automounting disks and USB drives."),
    "upowerd": ("UPower", "Reports battery and power status."),
    "wpa_supplicant": ("wpa_supplicant", "Handles Wi-Fi authentication."),
    "sshd": ("SSH server", "Remote login service. Ending this drops SSH sessions."),
    "containerd": ("containerd", "Container runtime. Ending this stops Docker/Kubernetes containers."),
    "dockerd": ("Docker", "The Docker daemon. Ending this stops all running containers."),
    "cron": ("cron", "Runs scheduled tasks."),
    "crond": ("cron", "Runs scheduled tasks."),
    "cupsd": ("CUPS", "The printing service."),
    "snapd": ("snapd", "Manages Snap package installs and updates."),
    "tailscaled": (
        "Tailscale",
        "Tailscale VPN daemon. Normal if you installed Tailscale; ending it drops that VPN.",
    ),
    "nvidia-persistenced": (
        "NVIDIA persistence daemon",
        "Keeps the NVIDIA GPU initialized. Expected on a machine with NVIDIA drivers.",
    ),
    "nvidia-persiste": (
        "NVIDIA persistence daemon",
        "Keeps the NVIDIA GPU initialized. Expected on a machine with NVIDIA drivers.",
    ),
    "vino-server": (
        "GNOME remote desktop (Vino)",
        "VNC/remote-desktop server. Verify you meant to allow remote control of this machine.",
    ),
    "master": (
        "Postfix (master)",
        "Mail-server supervisor. Only needed if this computer sends/receives email. If you never set up mail, check why Postfix is enabled.",
    ),
    "qmgr": (
        "Postfix (queue manager)",
        "Moves queued email. Part of Postfix; leave it if you use local mail, otherwise investigate.",
    ),
    "pickup": (
        "Postfix (pickup)",
        "Picks up locally submitted email. Part of Postfix.",
    ),
    "dconf-service": (
        "dconf",
        "Stores GNOME/desktop settings. Idle is normal. Don't kill it.",
    ),
    "goa-daemon": (
        "GNOME Online Accounts",
        "Holds Google/Microsoft/email account tokens for GNOME. Idle is normal.",
    ),
    "gvfsd": (
        "GVFS",
        "GNOME virtual filesystem — USB drives, Trash, MTP phones, remote files.",
    ),
    "mux": (
        "ROS 2 topic mux",
        "Robotics: multiplexes ROS 2 topics (topic_tools mux). Part of your robot stack, not a generic Ubuntu service.",
    ),
}

# Prefix on comm (lower) -> (friendly name, description)
KNOWN_PREFIXES: tuple[tuple[str, str, str], ...] = (
    ("gsd-", "GNOME Settings Daemon", "Desktop settings helper (keyboard, power, sound, display, accessibility). Idle is normal."),
    ("gvfsd", "GVFS helper", "GNOME virtual filesystem helper (USB, Trash, cameras, remote files)."),
    ("gvfs-", "GVFS helper", "GNOME virtual filesystem helper (USB, Trash, cameras, remote files)."),
    ("ibus-", "IBus", "Keyboard / input-method infrastructure. Needed for typing, especially non-English layouts."),
    ("evolution-", "Evolution data server", "GNOME calendar/contacts/accounts backend. Can run even if you don't use the Evolution mail app."),
    ("xdg-desktop-portal", "Desktop portal", "Lets apps do file dialogs, screenshots, screen sharing, and sandbox permissions."),
    ("xdg-document-portal", "Document portal", "Sandbox file access for Flatpak/Snap apps."),
    ("xdg-permission-store", "Permission store", "Remembers sandbox permissions for portals."),
)

FALLBACK_DESCRIPTIONS: dict[str, str] = {
    "app": "One of your desktop applications.",
    "background": "A background helper running in your session — usually tied to one of your apps.",
    "system": "A system service. Generally safe to leave running; look it up before ending it if unsure.",
    "kernel": "A kernel worker thread — part of Linux itself, not something you can usefully end here.",
}

# Back-compat alias used by older tests/callers.
KNOWN_SYSTEM = {k: v[1] for k, v in KNOWN_SERVICES.items()}


def python_script(cmdline: str) -> str:
    """Best-effort script/module path from a Python command line."""
    parts = cmdline.split()
    started = False
    for part in parts:
        base = Path(part).name
        if not started:
            if base.startswith("python") or part.startswith("-"):
                if part in ("-m",):
                    started = True
                continue
            started = True
        if part.startswith("-"):
            continue
        return part
    return ""


def is_ros_cmdline(cmdline: str, exe: str = "") -> bool:
    blob = f"{cmdline} {exe}".lower()
    return any(
        token in blob
        for token in ("/opt/ros/", "ros2", "rclpy", "rclcpp", "topic_tools", "ament_", "colcon")
    )


def explain(
    comm: str,
    kind: str = "system",
    pid: str = "",
    cmdline: str = "",
    exe: str = "",
) -> tuple[str, str]:
    """Return (friendly name, one-line description)."""
    lower = comm.lower()
    cmd = cmdline or ""

    if lower == "systemd" or comm == "systemd":
        if str(pid) == "1":
            return (
                "systemd (PID 1)",
                "The core system and service manager (PID 1). Never end this.",
            )
        return (
            "systemd --user",
            "Your per-user systemd instance — manages services in this login session, "
            "not the machine-wide PID 1. Ending it can still break the desktop session.",
        )

    if comm in KNOWN_APPS:
        return KNOWN_APPS[comm]

    if lower in KNOWN_SERVICES:
        return KNOWN_SERVICES[lower]

    for prefix, name, desc in KNOWN_PREFIXES:
        if lower.startswith(prefix):
            return (f"{name} ({comm})", desc)

    if is_ros_cmdline(cmd, exe):
        script = python_script(cmd) if comm.startswith("python") else ""
        label = Path(script).name if script else comm
        return (
            f"ROS 2 · {label}",
            "Robotics: a ROS 2 node or helper (not a generic Ubuntu service). "
            f"Command: {cmd[:180] or exe or comm}",
        )

    if comm.startswith("python"):
        script = python_script(cmd)
        if script:
            return (
                f"Python · {Path(script).name}",
                f"Python process running {script}",
            )
        if cmd:
            return ("Python", f"Python process: {cmd[:180]}")

    return (comm, FALLBACK_DESCRIPTIONS.get(kind, ""))


def friendly_name(comm: str, pid: str = "", cmdline: str = "", exe: str = "", kind: str = "system") -> str:
    return explain(comm, kind, pid=pid, cmdline=cmdline, exe=exe)[0]


def describe(comm: str, kind: str, pid: str = "", cmdline: str = "", exe: str = "") -> str:
    return explain(comm, kind, pid=pid, cmdline=cmdline, exe=exe)[1]


RISK_LABELS = {
    "safe": "Safe to end",
    "caution": "Use caution",
    "critical": "Critical — avoid ending",
}

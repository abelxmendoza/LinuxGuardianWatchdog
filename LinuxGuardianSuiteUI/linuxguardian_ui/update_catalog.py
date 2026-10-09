"""Turn package names into something a person can read.

apt and snap speak in package names (`libkrb5-3`, `linux-modules-5.15.0-164-generic`). This module groups them
under plain headings ("Security & encryption", "Web browsers", "Robotics (ROS 2 & Gazebo)"), gives the common
ones a human name ("Firefox", "OpenSSL library"), and reads apt's install output as it streams so the UI can say
what is being updated and what finished, without showing a terminal. The raw package names are never thrown away:
every friendly name keeps its real package name and versions alongside it.

Pure Python, no GTK, so it is fully unit-tested.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Group:
    id: str
    title: str
    blurb: str
    order: int


GROUPS: dict[str, Group] = {g.id: g for g in (
    Group("kernel", "Linux kernel & drivers", "The core of the operating system. A restart is needed before a new kernel is used.", 0),
    Group("security", "Security & encryption", "Libraries that protect logins, connections and files (certificates, encryption, authentication).", 1),
    Group("system", "Core system", "The foundations everything else runs on: C library, system services, package manager, disk tools.", 2),
    Group("browsers", "Web browsers & mail", "Firefox, Chromium and friends. Browsers are the most attacked apps on a computer, so these matter.", 3),
    Group("apps", "Apps", "Applications you installed (Claude, Cursor, Tailscale, VS Code, ...).", 4),
    Group("graphics", "Graphics & NVIDIA drivers", "Drivers and libraries for your screen and graphics card.", 5),
    Group("desktop", "Desktop & GNOME", "The desktop you click around in: windows, menus, fonts, settings.", 6),
    Group("network", "Networking & internet", "Connecting to Wi-Fi, networks and the internet (curl, NetworkManager, DNS).", 7),
    Group("robotics", "Robotics (ROS 2 & Gazebo)", "Your robot software stack: ROS 2, Gazebo and their tools.", 8),
    Group("python", "Python", "Python itself and Python libraries installed through Ubuntu.", 9),
    Group("dev", "Developer tools", "Compilers, build tools, git and the header files used to build software.", 10),
    Group("media", "Audio, video & images", "Playing and processing sound, video and pictures.", 11),
    Group("office", "Documents & office", "Document viewers and office software.", 12),
    Group("printing", "Printing", "Printer support.", 13),
    Group("libs", "Supporting libraries", "Shared building blocks that other software uses. Updated automatically alongside what depends on them.", 14),
    Group("other", "Other software", "Everything else.", 15),
)}

# (group id, regex on the package name), first match wins. Order matters: specific before general.
_RULES: list[tuple[str, re.Pattern[str]]] = [(g, re.compile(p)) for g, p in (
    ("kernel", r"^(linux-(image|modules|modules-extra|headers|tools|buildinfo|cloud-tools|generic|lowlatency|oem|signed|restricted|hwe|firmware)\b.*|linux-firmware|intel-microcode|amd64-microcode)$"),
    ("graphics", r"^(nvidia-.*|libnvidia-.*|xserver-xorg.*|mesa-.*|libgl1.*|libglx.*|libegl.*|libgles.*|libdrm.*|libvulkan.*|cuda.*|libcu(blas|dnn|fft|rand|solver|sparse|pti).*|nsight.*|libglapi.*|libgbm.*|libva.*|libvdpau.*)$"),
    ("browsers", r"^(firefox.*|chromium.*|google-chrome.*|thunderbird.*|epiphany.*)$"),
    ("robotics", r"^(ros-.*|ros2.*|gz-.*|libgz-.*|ignition-.*|libignition-.*|gazebo.*|libgazebo.*|libsdformat.*|sdformat.*|python3-(colcon|rosdep|vcstool|rosinstall|catkin|ament|rospkg).*|libopencv.*|mavros.*|libfastrtps.*|libfastcdr.*|libyaml-cpp.*|libconsole-bridge.*|libtinyxml2.*|libspdlog.*)$"),
    ("security", r"^(openssl|libssl.*|libgnutls.*|gnutls.*|libgcrypt.*|gnupg.*|gpg.*|libgpg.*|gpgv|dirmngr|ca-certificates|libnss.*|libnspr.*|openssh.*|libssh.*|sudo|apparmor.*|libapparmor.*|polkit.*|policykit.*|libpolkit.*|ufw|krb5.*|libkrb5.*|libk5crypto.*|libgssapi.*|libgssrpc.*|libkadm5.*|libkdb5.*|libaudit.*|libpam.*|pam.*|libsasl.*|libseccomp.*|libcap.*|libselinux.*|libsepol.*|libsodium.*|libtasn1.*|libp11-kit.*|p11-kit.*|libidn.*|libldap.*|ldap-utils|libnettle.*|libhogweed.*|libunbound.*|clamav.*|libclamav.*|rkhunter|libtss.*|tpm.*)$"),
    ("network", r"^(curl|libcurl.*|wget|network-manager.*|libnm.*|netplan.*|libnetplan.*|dnsmasq.*|avahi.*|libavahi.*|bind9.*|iproute2|iputils.*|openvpn.*|wpasupplicant|libwpa.*|ppp|libppp.*|nftables|libnftables.*|iptables|libip4tc.*|libip6tc.*|libnl-.*|rsync|ethtool|net-tools|libmbim.*|libqmi.*|modemmanager|libmm-glib.*|bluez.*|libbluetooth.*|samba.*|libsmbclient.*|libwbclient.*|cifs-utils|tcpdump|libpcap.*|nmap.*|tailscale.*|ufw)$"),
    ("python", r"^(python3?(\.\d+)?(-.*)?|libpython.*|python-.*|pip|python3-pip)$"),
    ("desktop", r"^(gnome-.*|libgnome.*|gdm3?|libgdm.*|mutter.*|libmutter.*|nautilus.*|libnautilus.*|gtk.*|libgtk.*|libgdk.*|libglib.*|glib.*|libgio.*|libpango.*|libcairo.*|libharfbuzz.*|libfontconfig.*|fontconfig.*|libfreetype.*|fonts-.*|adwaita.*|yaru.*|ubuntu-(desktop|session|settings|mono).*|dconf.*|libdconf.*|gsettings.*|xdg-.*|x11-.*|libx11.*|libxcb.*|libxkb.*|libxrandr.*|libxext.*|libxrender.*|libxi6.*|libwayland.*|wayland.*|libgraphene.*|libadwaita.*|libhandy.*|gjs|libgjs.*|libgweather.*|evolution-data-server.*|libedataserver.*|libecal.*|xorg.*|xwayland|libinput.*|libevdev.*|libatk.*|at-spi.*|libatspi.*|libsoup.*|webkit.*|libwebkit.*|libjavascriptcoregtk.*)$"),
    ("printing", r"^(cups.*|libcups.*|ghostscript.*|libgs.*|printer-driver.*|hplip.*|libsane.*|sane-.*)$"),
    ("office", r"^(libreoffice.*|evince.*|libevince.*|poppler.*|libpoppler.*|ure|uno-libs.*|python3-uno|fonts-opensymbol)$"),
    ("media", r"^(ffmpeg|libav.*|libsw(scale|resample).*|libpostproc.*|gstreamer.*|libgstreamer.*|libgst.*|vlc.*|libvlc.*|pulseaudio.*|libpulse.*|pipewire.*|libpipewire.*|libspa.*|alsa-.*|libasound.*|libpng.*|libjpeg.*|libtiff.*|libwebp.*|libopenjp2.*|imagemagick.*|libmagick.*|libgd3|libheif.*|libavif.*|libx26[45].*|libvpx.*|libopus.*|libvorbis.*|libogg.*|libflac.*|libmp3lame.*|libsndfile.*|totem.*|rhythmbox.*|shotwell.*|libexif.*)$"),
    ("dev", r"^(gcc.*|g\+\+.*|cpp.*|libgcc.*|libstdc\+\+.*|libgomp.*|libasan.*|libubsan.*|libtsan.*|cmake.*|make|git.*|build-essential|binutils.*|libbinutils.*|gdb.*|clang.*|libclang.*|llvm.*|libllvm.*|nodejs|npm|golang.*|rustc.*|cargo.*|libc6-dev|linux-libc-dev|pkg-config|pkgconf.*|autoconf|automake|libtool|ninja-build|ccache|valgrind|strace|dpkg-dev|libc-dev-bin|libc-devtools|.*-dev|.*-dbg|.*-dbgsym)$"),
    ("system", r"^(systemd.*|libsystemd.*|udev|libudev.*|dbus.*|libdbus.*|util-linux.*|libc6|libc-bin|libc-.*|locales.*|tzdata|coreutils|bash|dash|grub.*|initramfs-tools.*|apt.*|libapt.*|dpkg|libdpkg.*|snapd|e2fsprogs|libext2fs.*|libcom-err.*|libblkid.*|libmount.*|libsmartcols.*|libfdisk.*|libuuid.*|zlib.*|libzstd.*|liblzma.*|xz-utils|libbz2.*|bzip2|tar|gzip|libncurses.*|ncurses-.*|libtinfo.*|libreadline.*|readline-common|libsqlite3.*|sqlite3|libxml2.*|libicu.*|libexpat.*|expat|vim.*|nano|findutils|grep|sed|gawk|mawk|libpcre.*|libacl.*|libattr.*|login|passwd|mount|fdisk|procps|libprocps.*|psmisc|cron|logrotate|rsyslog|lsb-release|ubuntu-.*|base-files|libmd0|libgmp.*|libmpfr.*|libffi.*|libgpm.*|libyaml.*|libjson-c.*|libcrypt.*|libnss-.*|multiarch-support|libfuse.*|fuse.*|libfwupd.*|fwupd.*|libpolkit.*|libglib2.*|man-db|libmagic.*|file|netbase|iputils-ping|plymouth.*|libplymouth.*|kmod|libkmod.*|libaio.*|libbpf.*|libelf.*|elfutils|libdw.*)$"),
)]

# Names a person would recognise.
_FRIENDLY: dict[str, str] = {
    "firefox": "Firefox", "chromium": "Chromium", "chromium-browser": "Chromium", "google-chrome-stable": "Google Chrome",
    "thunderbird": "Thunderbird", "code": "Visual Studio Code", "cursor": "Cursor", "claude-desktop": "Claude Desktop",
    "chatgpt": "ChatGPT Desktop", "grok-bot": "Grok Bot", "tailscale": "Tailscale", "foxglove-studio": "Foxglove Studio",
    "speedtest": "Speedtest CLI", "spotify": "Spotify", "postman": "Postman", "slack": "Slack", "discord": "Discord",
    "snap-store": "App Store (Snap Store)", "snapd": "Snap service", "arduino": "Arduino IDE", "arduino-cli": "Arduino CLI",
    "jupyterlab-desktop": "JupyterLab Desktop", "mysql-shell": "MySQL Shell", "nmap": "Nmap", "htop": "htop", "node": "Node.js",
    "go": "Go", "rustup": "Rust toolchain", "gazebo": "Gazebo", "cups": "Printing service (CUPS)", "curl": "curl",
    "openssl": "OpenSSL", "libssl3": "OpenSSL library", "libssl-dev": "OpenSSL developer files", "libc6": "C library (glibc)",
    "libc-bin": "C library tools", "libc6-dev": "C library developer files", "systemd": "System manager (systemd)",
    "libsystemd0": "System manager library", "udev": "Device manager (udev)", "sudo": "sudo", "openssh-client": "SSH client",
    "openssh-server": "SSH server", "ca-certificates": "Trusted certificate list", "gnupg": "GnuPG (encryption)",
    "network-manager": "NetworkManager (Wi-Fi & networks)", "gdm3": "Login screen (GDM)", "mutter": "Window manager (Mutter)",
    "nautilus": "Files", "apparmor": "AppArmor (app confinement)", "ufw": "Firewall (ufw)", "python3": "Python 3",
    "git": "Git", "cmake": "CMake", "build-essential": "Build tools", "tzdata": "Time zone data", "dpkg": "Package installer (dpkg)",
    "apt": "Package manager (apt)", "grub-common": "Boot loader (GRUB)", "ubuntu-drivers-common": "Ubuntu driver tools",
}

_KERNEL_RE = re.compile(r"^linux-(image|modules|modules-extra|headers|tools|buildinfo|cloud-tools)-(\d[\w.\-]*?)(-generic|-lowlatency|-oem)?$")
_ARCH_RE = re.compile(r":(amd64|i386|arm64|armhf|all)$")


def base_name(name: str) -> str:
    return _ARCH_RE.sub("", name)


def classify(name: str, category: str | None = None) -> Group:
    """Which plain-language group a package belongs to. Vendor/snap apps are 'apps' unless they are clearly something else."""
    n = base_name(name)
    if category in ("snap", "third_party") and not any(r.match(n) for g, r in _RULES if g in ("robotics", "graphics", "kernel", "browsers")):
        return GROUPS["apps"]
    for gid, rx in _RULES:
        if rx.match(n):
            return GROUPS[gid]
    if n in _FRIENDLY:
        return GROUPS["apps"]
    if n.startswith("lib"):
        return GROUPS["libs"]
    return GROUPS["other"]


def friendly_name(name: str) -> str:
    """A name a person recognises. Falls back to a tidied version of the package name, never an empty string."""
    n = base_name(name)
    if n in _FRIENDLY:
        return _FRIENDLY[n]
    m = _KERNEL_RE.match(n)
    if m:
        kind = {"image": "Linux kernel", "modules": "Kernel modules", "modules-extra": "Extra kernel modules",
                "headers": "Kernel developer files", "tools": "Kernel tools", "buildinfo": "Kernel build info",
                "cloud-tools": "Kernel cloud tools"}[m.group(1)]
        return f"{kind} {m.group(2)}"
    if re.match(r"^linux-(generic|image-generic|headers-generic|image-generic-hwe|headers-generic-hwe)[\w.\-]*$", n):
        return "Linux kernel (latest)"
    m = re.match(r"^(nvidia-driver|nvidia-dkms|nvidia-utils|nvidia-compute-utils|nvidia-kernel-source|nvidia-kernel-common)-(\d+)", n)
    if m:
        return f"NVIDIA {m.group(1).split('-', 1)[1].replace('-', ' ')} {m.group(2)}"
    if n.startswith("libnvidia-"):
        return "NVIDIA library: " + re.sub(r"-\d+(-server)?$", "", n[len("libnvidia-"):]).replace("-", " ")
    m = re.match(r"^ros-([a-z]+)-(.+)$", n)
    if m:
        return f"ROS 2 {m.group(1).title()}: {m.group(2).replace('-', ' ')}"
    m = re.match(r"^python3-(.+)$", n)
    if m:
        return f"Python: {m.group(1).replace('-', ' ')}"
    if n.startswith("lib"):
        core = re.sub(r"(-[\d.]+)+$", "", n[3:]) or n[3:]
        if core.endswith("-dev"):
            return f"{core[:-4].replace('-', ' ')} developer files"
        if re.search(r"-(tools|utils|common|bin|data|doc|locales|multidev)$", core):
            return core.replace("-", " ")                      # libpng-tools is a tool set, not "a library"
        return f"{core.replace('-', ' ')} library"
    if n.endswith("-dev"):
        return f"{n[:-4].replace('-', ' ')} developer files"
    return n.replace("-", " ")


def group_items(items: list[dict], key: str = "name") -> list[tuple[Group, list[dict]]]:
    """[(group, items)] in display order; each item list sorted by friendly name. Items need a 'name' (and optionally 'category')."""
    buckets: dict[str, list[dict]] = {}
    for item in items:
        buckets.setdefault(classify(item[key], item.get("category")).id, []).append(item)
    out = []
    for gid in sorted(buckets, key=lambda g: GROUPS[g].order):
        out.append((GROUPS[gid], sorted(buckets[gid], key=lambda i: friendly_name(i[key]).lower())))
    return out


def headline(items: list[dict], key: str = "name", limit: int = 3) -> str:
    """'Firefox, Chromium, +2 more' for a group heading. Prefers recognisable names over libraries."""
    names = []
    for item in items:
        f = friendly_name(item[key])
        if f not in names:
            names.append(f)
    names.sort(key=lambda s: (s.endswith(" library") or s.endswith("developer files"), s.lower()))
    # "OpenSSL" and "OpenSSL library" are one thing to a reader: keep the shorter, don't repeat it.
    names = [n for i, n in enumerate(names) if not any(n.startswith(m + " ") for m in names[:i])]
    shown = names[:limit]
    extra = len(names) - len(shown)
    return ", ".join(shown) + (f", +{extra} more" if extra > 0 else "")


def plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


# ----------------------------------------------------------------------- reading apt's output
_UNPACK_RE = re.compile(r"^Unpacking (\S+) \(([^)]*)\)(?: over \(([^)]*)\))?")
_SETUP_RE = re.compile(r"^Setting up (\S+) \(([^)]*)\)")
_SNAP_RE = re.compile(r"^(\S+) (\S+) from .* refreshed\s*$")
_SUMMARY_RE = re.compile(r"^(\d+) upgraded, (\d+) newly installed, (\d+) to remove")
_PLANNED_RE = re.compile(r"^Packages that will be upgraded:\s*(.*)$")       # unattended-upgrade -v


@dataclass
class Done:
    name: str
    new: str
    old: str = ""
    manager: str = "apt"


@dataclass
class InstallLog:
    """Feed it apt/snap output lines as they stream; it keeps what is being worked on and what finished."""
    current: str = ""                                    # friendly name of what apt is unpacking/configuring right now
    done: dict[str, Done] = field(default_factory=dict)
    _old: dict[str, str] = field(default_factory=dict)
    expected: int | None = None                          # "N upgraded, M newly installed" from apt, when it said so
    planned: list[str] = field(default_factory=list)     # names unattended-upgrade announced (it prints no per-package lines)

    def feed(self, line: str) -> str | None:
        """Returns 'working' | 'done' | 'snap' | 'summary' when the line meant something, else None."""
        line = line.strip()
        m = _UNPACK_RE.match(line)
        if m:
            name = base_name(m.group(1))
            self.current = friendly_name(name)
            if m.group(3):
                self._old[name] = m.group(3)
            return "working"
        m = _SETUP_RE.match(line)
        if m:
            name = base_name(m.group(1))
            self.current = friendly_name(name)
            self.done[name] = Done(name, m.group(2), self._old.get(name, ""))
            return "done"
        m = _SNAP_RE.match(line)
        if m:
            self.done[m.group(1)] = Done(m.group(1), m.group(2), "", "snap")
            self.current = friendly_name(m.group(1))
            return "snap"
        m = _SUMMARY_RE.match(line)
        if m:
            self.expected = int(m.group(1)) + int(m.group(2))
            return "summary"
        m = _PLANNED_RE.match(line)
        if m and m.group(1).strip():
            self.planned = [base_name(n) for n in m.group(1).split()]
            self.expected = len(self.planned)
            return "summary"
        return None

    def complete_from_plan(self, pending: dict[str, tuple[str, str]]) -> None:
        """After a successful run: anything announced but never reported individually was installed too.
        `pending` maps package name -> (old version, new version) from the check made before installing."""
        for name in self.planned:
            if name not in self.done:
                old, new = pending.get(name, ("", ""))
                self.done[name] = Done(name, new, old)

    def fraction(self, fallback_total: int = 0) -> float | None:
        total = self.expected or fallback_total
        if not total:
            return None
        return min(0.97, len(self.done) / total)

    def items(self) -> list[dict]:
        """Finished updates in the shape the page's groupers expect."""
        return [{"name": d.name, "installed": d.old, "candidate": d.new, "manager": d.manager,
                 "category": "snap" if d.manager == "snap" else None} for d in self.done.values()]

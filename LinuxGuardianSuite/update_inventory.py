#!/usr/bin/env python3
"""Inventory pending software updates (apt + snap) without needing root.

Everything here is read-only: `apt-get -s upgrade` simulates, and
`snap refresh --list` only asks the store what is newer. Used by
linux_updates.sh and by the GUI's Updates page.

Besides the pending list this also answers two safety questions:

  * Release guard: is every update source (and every pending package) from the
    Ubuntu release this machine is running? If something points at a different
    release, installing is blocked, so a stray sources edit can never quietly
    turn a routine update into a half-finished release upgrade.
  * Pinned stacks: which groups of packages (ROS 2, Gazebo, NVIDIA/CUDA) are
    held with `apt-mark hold`, so the owner can freeze a working robotics or
    GPU stack on purpose.

Output modes:
  (default)   JSON lines: one {"type": "meta"} line, then {"type": "pkg"} lines.
  --text      Human-readable summary.
  --summary   One `key=value` line of counts (for shell scripts).
  --guard     Release guard only. Exit 0 = ok, 3 = blocked (reasons on stdout).
  --hold-names GROUP / --unhold-names GROUP
              Package names that `apt-mark hold` / `unhold` should act on.

Test hooks (read-only inputs, never used for anything privileged):
  LG_APT_ROOT=/path        use this instead of /etc/apt
  LG_OS_RELEASE_FILE=/path use this instead of /etc/os-release
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

# Text categories, in the order the UI shows them.
SECURITY = "security"
STANDARD = "standard"
THIRD_PARTY = "third_party"
SNAP = "snap"

# `Inst NAME [OLD] (NEW ORIGIN[, ORIGIN...] [ARCH]) ...trailing dep groups`
# Real output often has extra "[...]" groups after the closing paren, so this
# deliberately does NOT anchor at the end of the line.
_INST_RE = re.compile(
    r"^Inst (?P<name>\S+) (?:\[(?P<old>[^\]]+)\] )?\((?P<new>\S+) (?P<origin>.+?) \[(?P<arch>[^\]]+)\]\)"
)

_REBOOT_FLAG = Path("/var/run/reboot-required")
_APT_STAMPS = (
    Path("/var/lib/apt/periodic/update-success-stamp"),
    Path("/var/lib/apt/lists"),
)

# Names of Ubuntu/Debian releases. A source whose suite is one of these but is
# not *this* machine's release is a mixed-release setup. Deliberately excludes
# aliases like "stable"/"testing": vendors use "stable" for their own channels.
KNOWN_RELEASE_CODENAMES = frozenset(
    {
        "trusty", "xenial", "bionic", "focal", "jammy", "kinetic", "lunar",
        "mantic", "noble", "oracular", "plucky", "questing",
        "buster", "bullseye", "bookworm", "trixie", "forky", "sid", "devel",
    }
)
# On these hosts the suite *is* an Ubuntu release name, whatever it is called.
_UBUNTU_HOST_RE = re.compile(r"(^|\.)(ubuntu\.com|launchpad\.net|launchpadcontent\.net)$")
_UBUNTU_ORIGIN_RE = re.compile(r"^Ubuntu(?:ESM)?[^:/\s]*:[\d.]+/(?P<suite>[A-Za-z0-9._+-]+)")

# Debian package-name rules, minus uppercase: lowercase alnum then [a-z0-9+.-],
# with an optional ":arch" qualifier. Nothing that could be read as an option
# (leading '-') or shell syntax gets through.
PACKAGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9+.:-]*$")

# Stacks the owner can freeze. Patterns are exact on purpose: an over-broad
# prefix (e.g. "libcu") would also hold libcurl4/libcups2 and block *their*
# security fixes, which is the opposite of what holding a stack is for.
HOLD_GROUPS: tuple[dict, ...] = (
    {
        "id": "ros2",
        "label": "ROS 2 (robotics stack)",
        "blurb": "Your ros-<distro>-* packages. Freezing them keeps a working robot workspace from "
        "changing underneath you when ROS publishes a sync.",
        # Real distro names only: a bare "ros-[a-z]+-" would also catch
        # repo-config packages like ros-apt-source, which aren't part of the stack.
        "pattern": re.compile(
            r"^ros-(?:humble|iron|jazzy|kilted|rolling|galactic|foxy|eloquent|dashing|noetic|melodic|kinetic)-"
        ),
    },
    {
        "id": "gazebo",
        "label": "Gazebo simulator",
        "blurb": "Gazebo / Ignition libraries from the OSRF repository.",
        "pattern": re.compile(
            r"^(gz-|libgz-|gazebo|libgazebo|ignition-|libignition-|sdformat|libsdformat)"
        ),
    },
    {
        "id": "nvidia",
        "label": "NVIDIA driver & CUDA",
        "blurb": "GPU driver, CUDA toolkit and the container toolkit. A driver change can break the "
        "display or CUDA builds, so freeze this once it works.",
        "pattern": re.compile(
            r"^(nvidia-|libnvidia-|xserver-xorg-video-nvidia|cuda-|libcublas|libcudnn|libcufft|"
            r"libcufile|libcurand|libcusolver|libcusparse|libcupti|libnccl|libnpp|libnvjpeg|"
            r"libnvjitlink|libnvinfer|tensorrt)"
        ),
    },
)


# --------------------------------------------------------------------------
# apt / snap pending updates
# --------------------------------------------------------------------------
def classify_origin(origin: str) -> str:
    """Bucket an apt origin string like 'Ubuntu:22.04/jammy-updates, ...'.

    Security wins if *any* origin carrying the candidate is a -security
    pocket (or ESM infra), because that is what unattended-upgrades and
    Ubuntu's own tooling treat as a security fix. Anything that isn't an
    Ubuntu origin came from a repository the user (or an installer) added.
    """
    parts = [p.strip() for p in origin.split(",") if p.strip()]
    if any("-security" in p or p.startswith("UbuntuESM") for p in parts):
        return SECURITY
    if any(p.startswith("Ubuntu:") or p.startswith("Ubuntu ") for p in parts):
        return STANDARD
    return THIRD_PARTY


def parse_apt_simulation(text: str) -> tuple[list[dict], list[str]]:
    """Parse `apt-get -s upgrade` output into (upgrades, kept_back_names)."""
    upgrades: list[dict] = []
    kept_back: list[str] = []
    in_kept = False
    for line in text.splitlines():
        if line.startswith("The following packages have been kept back:"):
            in_kept = True
            continue
        if in_kept:
            if line.startswith("  "):
                kept_back.extend(line.split())
                continue
            in_kept = False
        match = _INST_RE.match(line)
        if not match:
            continue
        origin = match["origin"]
        upgrades.append(
            {
                "type": "pkg",
                "manager": "apt",
                "name": match["name"],
                "installed": match["old"] or "",
                "candidate": match["new"],
                "arch": match["arch"],
                "origin": origin,
                "category": classify_origin(origin),
            }
        )
    return upgrades, kept_back


def parse_snap_refresh(text: str) -> list[dict]:
    """Parse the table printed by `snap refresh --list`."""
    pkgs: list[dict] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] == "Name":
            continue
        pkgs.append(
            {
                "type": "pkg",
                "manager": "snap",
                "name": fields[0],
                "installed": "",
                "candidate": fields[1],
                "rev": fields[2],
                "size": fields[3],
                "origin": fields[4].rstrip("*"),
                "notes": " ".join(fields[5:]),
                "category": SNAP,
            }
        )
    return pkgs


def _run(cmd: list[str], timeout: float) -> str | None:
    """Run a fixed command in the C locale; None if it failed or timed out."""
    env = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout


def cache_age_sec() -> int | None:
    for path in _APT_STAMPS:
        try:
            return max(0, int(time.time() - path.stat().st_mtime))
        except OSError:
            continue
    return None


def reboot_status() -> dict:
    needed = _REBOOT_FLAG.exists()
    pkgs: list[str] = []
    if needed:
        try:
            pkgs = _REBOOT_FLAG.with_suffix(".pkgs").read_text().split()
        except OSError:
            pass
    return {"reboot_required": needed, "reboot_pkgs": sorted(set(pkgs))}


def auto_security_status() -> dict:
    """Are automatic security updates *actually on*, not merely installed?

    Needs all of: the unattended-upgrade tool present, APT's periodic machinery not disabled
    (Enable "0" turns every periodic job off), package lists refreshed periodically (otherwise
    there is nothing new to upgrade), the periodic upgrade setting non-zero, and the daily systemd
    timer both enabled and running. Even then this proves configuration, not that an update
    recently succeeded; the unattended-upgrades logs show that.
    """
    installed = shutil.which("unattended-upgrade") is not None
    dump = _run(["apt-config", "dump"], 10) or ""

    def periodic(name: str) -> int:
        match = re.search(rf'^APT::Periodic::{name} "(\d+)";', dump, re.M)
        return int(match.group(1)) if match else 0

    configured = (
        periodic("Unattended-Upgrade") > 0
        and periodic("Update-Package-Lists") > 0
        and not re.search(r'^APT::Periodic::Enable "0";', dump, re.M)
    )
    timer = (_run(["systemctl", "is-enabled", "apt-daily-upgrade.timer"], 10) or "").strip()
    timer_active = (_run(["systemctl", "is-active", "apt-daily-upgrade.timer"], 10) or "").strip()
    timer_on = timer == "enabled" and timer_active == "active"
    return {
        "auto_security_updates": "on" if (installed and configured and timer_on) else "off",
        "auto_installed": installed,
        "auto_configured": configured,
        "auto_timer_enabled": timer_on,
    }


# --------------------------------------------------------------------------
# Release guard
# --------------------------------------------------------------------------
def _apt_root() -> Path:
    return Path(os.environ.get("LG_APT_ROOT", "/etc/apt"))


def _os_release_path() -> Path:
    return Path(os.environ.get("LG_OS_RELEASE_FILE", "/etc/os-release"))


def parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key] = value.strip().strip('"').strip("'")
    return out


def current_codename() -> str:
    """This machine's release codename ('jammy'). UBUNTU_CODENAME wins so
    Ubuntu derivatives (Mint, Pop!_OS) report the Ubuntu base they track."""
    try:
        data = parse_os_release(_os_release_path().read_text())
    except OSError:
        return ""
    return data.get("UBUNTU_CODENAME") or data.get("VERSION_CODENAME") or ""


def parse_apt_sources(text: str, deb822: bool) -> list[dict]:
    """Extract {uri, suites} entries from a sources file (either format)."""
    entries: list[dict] = []
    if deb822:
        for stanza in re.split(r"\n\s*\n", text):
            fields: dict[str, str] = {}
            for line in stanza.splitlines():
                # Continuation lines (armored Signed-By keys, etc.) start with
                # whitespace; comments start with '#'.
                if not line.strip() or line[0] in " \t" or line.lstrip().startswith("#"):
                    continue
                if ":" in line:
                    key, value = line.split(":", 1)
                    fields[key.strip().lower()] = value.strip()
            if not fields.get("uris") or not fields.get("suites"):
                continue
            if fields.get("enabled", "yes").lower() in ("no", "false"):
                continue
            for uri in fields["uris"].split():
                entries.append({"uri": uri, "suites": fields["suites"].split()})
        return entries

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line.startswith(("deb ", "deb-src ", "deb\t")):
            continue
        rest = line.split()[1:]
        if rest and rest[0].startswith("["):
            i = 0
            while i < len(rest) and not rest[i].endswith("]"):
                i += 1
            rest = rest[i + 1 :]
        if len(rest) >= 2:
            entries.append({"uri": rest[0], "suites": [rest[1]]})
    return entries


def read_apt_sources(root: Path) -> list[dict]:
    entries: list[dict] = []
    files: list[tuple[Path, bool]] = []
    main = root / "sources.list"
    if main.is_file():
        files.append((main, False))
    d = root / "sources.list.d"
    if d.is_dir():
        for path in sorted(d.iterdir()):
            if path.suffix == ".list":
                files.append((path, False))
            elif path.suffix == ".sources":
                files.append((path, True))
    for path, is_822 in files:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for entry in parse_apt_sources(text, is_822):
            entry["file"] = path.name
            entries.append(entry)
    return entries


def foreign_sources(entries: list[dict], current: str) -> list[str]:
    """Update sources that name a *different* release than the running one."""
    problems: list[str] = []
    for entry in entries:
        host = urlparse(entry["uri"]).hostname or ""
        on_ubuntu_host = bool(_UBUNTU_HOST_RE.search(host))
        for suite in entry["suites"]:
            # Flat repositories use "/" (e.g. local CUDA/L4T repos) — no release.
            if suite.startswith("/") or not re.search(r"[a-z]", suite):
                continue
            base = suite.split("-")[0].lower()
            if base == current:
                continue
            if base in KNOWN_RELEASE_CODENAMES or on_ubuntu_host:
                where = host or entry["uri"]
                problems.append(
                    f"Update source {where} ({entry.get('file', '?')}) is for '{base}', "
                    f"but this system is '{current}'."
                )
    return list(dict.fromkeys(problems))


def foreign_release_packages(pkgs: list[dict], current: str) -> list[str]:
    """Pending apt packages whose Ubuntu origin is a different release."""
    problems: list[str] = []
    for pkg in pkgs:
        if pkg.get("manager") != "apt":
            continue
        for part in pkg.get("origin", "").split(","):
            match = _UBUNTU_ORIGIN_RE.match(part.strip())
            if not match:
                continue
            base = match["suite"].split("-")[0].lower()
            if base != current:
                problems.append(
                    f"{pkg['name']} would come from {match['suite']}, "
                    f"but this system is '{current}'."
                )
    return list(dict.fromkeys(problems))


def release_guard(current: str, entries: list[dict], pkgs: list[dict], applicable: bool = True) -> dict:
    if not applicable:
        return {"ok": True, "applicable": False, "codename": current, "problems": []}
    problems: list[str] = []
    if not current:
        problems.append("Couldn't determine which release this system is running, so mixing can't be ruled out.")
    else:
        problems += foreign_sources(entries, current)
        problems += foreign_release_packages(pkgs, current)
    shown = problems[:6]
    if len(problems) > 6:
        shown.append(f"...and {len(problems) - 6} more.")
    return {"ok": not problems, "applicable": True, "codename": current, "problems": shown}


def _apt_present(root: Path) -> bool:
    return (root / "sources.list").exists() or (root / "sources.list.d").is_dir()


# --------------------------------------------------------------------------
# Pinned stacks (apt-mark hold)
# --------------------------------------------------------------------------
def _native_arch() -> str:
    return (_run(["dpkg", "--print-architecture"], 10) or "amd64").strip() or "amd64"


def normalize_pkg(name: str, arch: str) -> str:
    """'libfoo:amd64' and 'libfoo' are the same native package."""
    return name[: -len(arch) - 1] if name.endswith(f":{arch}") else name


def installed_packages() -> list[str]:
    out = _run(["dpkg-query", "-W", "-f", "${binary:Package}\t${db:Status-Abbrev}\n"], 30) or ""
    names: list[str] = []
    for line in out.splitlines():
        name, _, status = line.partition("\t")
        # Second char 'i' = installed; first char may be 'h' (on hold).
        if len(status) >= 2 and status[1] == "i":
            names.append(name)
    return names


def held_packages(arch: str) -> set[str]:
    out = _run(["apt-mark", "showhold"], 15) or ""
    return {normalize_pkg(n.strip(), arch) for n in out.splitlines() if n.strip()}


def parse_apt_upgradable(text: str) -> dict[str, dict]:
    """Parse `apt list --upgradable`: name -> {installed, candidate}."""
    found: dict[str, dict] = {}
    pattern = re.compile(r"^(?P<name>[^/\s]+)/\S+ (?P<cand>\S+) \S+ \[upgradable from: (?P<old>[^\]]+)\]")
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            found[match["name"]] = {"installed": match["old"], "candidate": match["cand"]}
    return found


def group_by_id(group_id: str) -> dict | None:
    return next((g for g in HOLD_GROUPS if g["id"] == group_id), None)


def hold_group_status(installed: list[str], held: set[str], arch: str) -> list[dict]:
    statuses: list[dict] = []
    for group in HOLD_GROUPS:
        members = [n for n in installed if group["pattern"].match(normalize_pkg(n, arch))]
        held_n = sum(1 for n in members if normalize_pkg(n, arch) in held)
        if not members:
            state = "absent"
        elif held_n == 0:
            state = "none"
        elif held_n == len(members):
            state = "all"
        else:
            state = "partial"
        statuses.append(
            {
                "id": group["id"],
                "label": group["label"],
                "blurb": group["blurb"],
                "installed": len(members),
                "held": held_n,
                "state": state,
            }
        )
    return statuses


def names_for_hold(group_id: str, release: bool) -> list[str] | None:
    """Package names `apt-mark hold` (or `unhold` if release) should act on.

    None for an unknown group. Anything that isn't a valid Debian package name
    is dropped here, and the root-side script checks again.
    """
    group = group_by_id(group_id)
    if group is None:
        return None
    arch = _native_arch()
    held = held_packages(arch)
    names: list[str] = []
    for name in installed_packages():
        norm = normalize_pkg(name, arch)
        if not group["pattern"].match(norm) or not PACKAGE_NAME_RE.match(name):
            continue
        if release == (norm in held):
            names.append(name)
    return sorted(set(names))


# --------------------------------------------------------------------------
# Collection and rendering
# --------------------------------------------------------------------------
def collect(include_snap: bool = True) -> tuple[dict, list[dict]]:
    pkgs: list[dict] = []
    kept_back: list[str] = []
    apt_ok = False
    if shutil.which("apt-get"):
        out = _run(["apt-get", "-s", "upgrade"], 90)
        if out is not None:
            apt_ok = True
            apt_pkgs, kept_back = parse_apt_simulation(out)
            pkgs.extend(apt_pkgs)

    snap_checked = False
    if include_snap and shutil.which("snap"):
        out = _run(["snap", "refresh", "--list"], 25)
        if out is not None:
            snap_checked = True
            pkgs.extend(parse_snap_refresh(out))

    root = _apt_root()
    codename = current_codename()
    guard = release_guard(
        codename,
        read_apt_sources(root),
        [p for p in pkgs if p["manager"] == "apt"],
        applicable=_apt_present(root),
    )

    arch = _native_arch()
    installed = installed_packages()
    held = held_packages(arch)
    groups = hold_group_status(installed, held, arch)
    grouped_patterns = [g["pattern"] for g in HOLD_GROUPS]
    held_other = sorted(h for h in held if not any(p.match(h) for p in grouped_patterns))[:100]
    held_with_updates: list[dict] = []
    if held:
        upgradable = parse_apt_upgradable(_run(["apt", "list", "--upgradable"], 60) or "")
        held_with_updates = [
            {"name": n, **info} for n, info in sorted(upgradable.items()) if normalize_pkg(n, arch) in held
        ][:100]

    meta = {
        "type": "meta",
        "apt_ok": apt_ok,
        "snap_checked": snap_checked,
        "apt_kept_back": kept_back,
        "cache_age_sec": cache_age_sec(),
        "os_codename": codename,
        "release_guard": guard,
        "hold_groups": groups,
        "held_other": held_other,
        "held_with_updates": held_with_updates,
        **reboot_status(),
        **auto_security_status(),
    }
    return meta, pkgs


def counts(pkgs: list[dict]) -> dict[str, int]:
    result = {SECURITY: 0, STANDARD: 0, THIRD_PARTY: 0, SNAP: 0}
    for pkg in pkgs:
        result[pkg["category"]] += 1
    return result


def fmt_age(seconds: int | None) -> str:
    if seconds is None:
        return "unknown"
    if seconds < 90:
        return "just now"
    if seconds < 5400:
        return f"{seconds // 60}m ago"
    if seconds < 172800:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def render_text(meta: dict, pkgs: list[dict]) -> str:
    c = counts(pkgs)
    guard = meta.get("release_guard", {})
    lines = [
        f"Package lists refreshed: {fmt_age(meta['cache_age_sec'])}",
        f"Automatic security updates: {meta['auto_security_updates'].upper()}",
        f"Restart required: {'YES (' + ', '.join(meta['reboot_pkgs']) + ')' if meta['reboot_required'] else 'no'}",
    ]
    if guard.get("applicable", False):
        if guard["ok"]:
            lines.append(f"Release guard: OK (all sources are for '{guard['codename']}')")
        else:
            lines.append("Release guard: BLOCKED. Installing is disabled until this is fixed:")
            lines.extend(f"  - {p}" for p in guard["problems"])
    lines += [
        "",
        f"Pending: {c[SECURITY]} security, {c[STANDARD]} other system, "
        f"{c[THIRD_PARTY]} third-party, {c[SNAP]} snap"
        + ("" if meta["snap_checked"] else " (snaps not checked)"),
    ]
    labels = {SECURITY: "Security", STANDARD: "System", THIRD_PARTY: "Third-party", SNAP: "Snap"}
    for category in (SECURITY, STANDARD, THIRD_PARTY, SNAP):
        for pkg in pkgs:
            if pkg["category"] == category:
                old = f"{pkg['installed']} -> " if pkg["installed"] else ""
                lines.append(f"  [{labels[category]}] {pkg['name']}  {old}{pkg['candidate']}")
    if meta["apt_kept_back"]:
        lines.append("")
        lines.append(
            f"Held back ({len(meta['apt_kept_back'])}): "
            + ", ".join(meta["apt_kept_back"][:8])
            + (" ..." if len(meta["apt_kept_back"]) > 8 else "")
        )
        lines.append("  These need a full upgrade (may add/remove packages); not done automatically.")
    groups = [g for g in meta.get("hold_groups", []) if g["state"] != "absent"]
    if groups or meta.get("held_other"):
        lines.append("")
        lines.append("Pinned stacks (frozen with apt-mark hold):")
        for g in groups:
            lines.append(f"  {g['label']}: {g['state']} ({g['held']} of {g['installed']} held)")
        if meta.get("held_other"):
            lines.append(f"  Also held outside LinuxGuardian: {', '.join(meta['held_other'][:8])}")
        if meta.get("held_with_updates"):
            lines.append(f"  {len(meta['held_with_updates'])} held package(s) have newer versions waiting.")
    return "\n".join(lines)


def render_summary(meta: dict, pkgs: list[dict]) -> str:
    c = counts(pkgs)
    return " ".join(
        [
            f"security={c[SECURITY]}",
            f"standard={c[STANDARD]}",
            f"third_party={c[THIRD_PARTY]}",
            f"snap={c[SNAP] if meta['snap_checked'] else '-'}",
            f"kept_back={len(meta['apt_kept_back'])}",
            f"reboot={1 if meta['reboot_required'] else 0}",
            f"auto_security={meta['auto_security_updates']}",
            f"apt_ok={1 if meta['apt_ok'] else 0}",
            f"cache_age_sec={meta['cache_age_sec'] if meta['cache_age_sec'] is not None else '-'}",
        ]
    )


def run_guard() -> int:
    """Release guard only (no snap query, no holds). Exit 0 ok / 3 blocked."""
    root = _apt_root()
    pkgs: list[dict] = []
    if shutil.which("apt-get"):
        out = _run(["apt-get", "-s", "upgrade"], 90)
        if out is not None:
            pkgs, _ = parse_apt_simulation(out)
    codename = current_codename()
    guard = release_guard(codename, read_apt_sources(root), pkgs, applicable=_apt_present(root))
    if guard["ok"]:
        print(f"OK: release guard passed (this system is '{codename or 'unknown'}').")
        return 0
    print("BLOCKED by the release guard:")
    for problem in guard["problems"]:
        print(f"  - {problem}")
    return 3


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--text", action="store_true", help="human-readable output")
    parser.add_argument("--summary", action="store_true", help="one key=value line of counts")
    parser.add_argument("--no-snap", action="store_true", help="skip the snap store query (it needs network)")
    parser.add_argument("--guard", action="store_true", help="release guard only; exit 3 if blocked")
    parser.add_argument("--hold-names", metavar="GROUP", help="packages to hold for a stack")
    parser.add_argument("--unhold-names", metavar="GROUP", help="packages to release for a stack")
    args = parser.parse_args()

    if args.guard:
        return run_guard()
    for flag, release in ((args.hold_names, False), (args.unhold_names, True)):
        if flag:
            names = names_for_hold(flag, release)
            if names is None:
                print(f"Unknown stack '{flag}'. Known: {', '.join(g['id'] for g in HOLD_GROUPS)}", file=sys.stderr)
                return 4
            print("\n".join(names))
            return 0

    meta, pkgs = collect(include_snap=not args.no_snap)
    if args.summary:
        print(render_summary(meta, pkgs))
    elif args.text:
        print(render_text(meta, pkgs))
    else:
        print(json.dumps(meta, ensure_ascii=False))
        for pkg in pkgs:
            print(json.dumps(pkg, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

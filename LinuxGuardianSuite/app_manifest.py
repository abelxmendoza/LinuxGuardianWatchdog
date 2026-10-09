#!/usr/bin/env python3
"""Move your apps to another laptop running the same Ubuntu.

  app_manifest.py --export [FILE]     write a manifest of what is installed here (read-only)
  app_manifest.py --plan FILE         what installing it on THIS machine would do (read-only)
  app_manifest.py --names FILE --kind apt|snap|snap-classic
                                      the validated package names the plan would install (for the installer)

The manifest is a plain JSON list of app names and where they came from. It contains NO files from your
home folder, no passwords, no keys, and any credentials in repository URLs are stripped.

What import will and won't do (the plan shows all of it before anything happens):
  * installs Ubuntu packages and snaps that are available on THIS machine
  * never adds a repository or a signing key: apps from third-party repos are listed with the repo they
    need, for you to add by hand if you trust it
  * skips hardware-specific packages (kernels, NVIDIA/CUDA/Jetson drivers, firmware): they belong to the
    machine, not to you
  * refuses entirely if the Ubuntu release or CPU architecture differs
  * classic snaps run unconfined, so they are installed only when you explicitly include them

Test hooks: LG_APT_ROOT, LG_OS_RELEASE_FILE; apt-mark/apt-cache/dpkg/snap/flatpak are found on PATH.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

import update_inventory as ui  # noqa: E402

SCHEMA = 1
SNAP_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")
FLATPAK_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{1,200}$")

# Belong to the machine (hardware, kernel, firmware, graphics stack), not to the person.
HARDWARE_RE = re.compile(
    r"^(linux-(image|headers|modules|modules-extra|tools|buildinfo|cloud-tools|oem|generic|lowlatency|signed|restricted)[-a-z0-9.]*"
    r"|linux-firmware|intel-microcode|amd64-microcode|firmware-.*|bcmwl-.*|broadcom-sta.*|r8168-dkms"
    r"|nvidia-.*|libnvidia-.*|xserver-xorg-video-.*|cuda.*|libcu(dnn|blas|fft|rand|solver|sparse|pti).*|nsight.*"
    r"|nvidia-l4t.*|.*-l4t-.*|.*jetson.*|tegra.*|.*-dkms|dkms|grub-.*|shim-.*|efibootmgr|ubuntu-drivers-common)$"
)
SNAP_SKIP = {"snapd", "bare", "core", "gtk-common-themes"}
_SNAP_SKIP_RE = re.compile(r"^(core\d*|gnome-[0-9-]+(-sdk)?|gnome-.*-.*-.*|mesa-.*|gtk-theme-.*|snapd-desktop-integration)$")


def _run(cmd: list[str], timeout: float = 60) -> str:
    return ui._run(cmd, timeout) or ""


# ------------------------------------------------------------------ collecting
def redact(uri: str) -> str:
    """Drop credentials from a repository URL."""
    parts = urlsplit(uri)
    if parts.username or parts.password:
        host = parts.hostname or ""
        if parts.port:
            host += f":{parts.port}"
        return parts._replace(netloc=host).geturl()
    return uri


def parse_policy(text: str) -> dict[str, dict]:
    """`apt-cache policy a b c` -> {name: {installed, candidate, origin_url}} for the INSTALLED version."""
    out: dict[str, dict] = {}
    blocks = re.split(r"\n(?=\S[^\n]*:\n)", text.strip("\n") + "\n")
    for block in blocks:
        lines = block.splitlines()
        if not lines or not lines[0].rstrip().endswith(":"):
            continue
        name = lines[0].strip().rstrip(":")
        info: dict = {"installed": None, "candidate": None, "origin_url": None}
        in_installed = False
        for line in lines[1:]:
            s = line.strip()
            if s.startswith("Installed:"):
                v = s.split(":", 1)[1].strip()
                info["installed"] = None if v == "(none)" else v
            elif s.startswith("Candidate:"):
                v = s.split(":", 1)[1].strip()
                info["candidate"] = None if v == "(none)" else v
            elif line.startswith(" *** "):
                in_installed = True
            elif re.match(r"^ {1,5}\S", line) and not line.startswith(" *** ") and re.match(r"^\s{1,5}\d+\.|^\s{1,5}[0-9a-zA-Z~+:.\-]+\s+\d+$", line):
                in_installed = False
            elif in_installed and re.match(r"^\s+\d+\s+(\S+)", line):
                url = re.match(r"^\s+\d+\s+(\S+)", line).group(1)
                if url != "/var/lib/dpkg/status" and info["origin_url"] is None:
                    info["origin_url"] = url
        out[name] = info
    return out


def classify_url(url: str | None) -> tuple[str, str | None]:
    """('ubuntu'|'third_party'|'local', host)"""
    if not url:
        return "local", None
    host = urlsplit(url).hostname or ""
    if ui._UBUNTU_HOST_RE.search(host):
        return "ubuntu", host
    return "third_party", host


def collect_apt(arch: str) -> list[dict]:
    names = sorted(n for n in (_run(["apt-mark", "showmanual"], 30).split()) if n)
    policy: dict[str, dict] = {}
    for i in range(0, len(names), 80):
        policy.update(parse_policy(_run(["apt-cache", "policy", *names[i : i + 80]], 120)))
    rows = []
    for name in names:
        info = policy.get(name, {})
        origin, host = classify_url(info.get("origin_url"))
        rows.append({
            "name": ui.normalize_pkg(name, arch), "version": info.get("installed"),
            "origin": origin, "host": host,
            "hardware_specific": bool(HARDWARE_RE.match(name)),
        })
    return rows


def collect_snaps() -> list[dict]:
    out = _run(["snap", "list"], 30)
    rows = []
    for line in out.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 6:
            continue
        name, notes = cols[0], cols[-1]
        if name in SNAP_SKIP or _SNAP_SKIP_RE.match(name) or "base" in notes.split(",") or "snapd" in notes.split(","):
            continue
        rows.append({"name": name, "channel": cols[3], "classic": "classic" in notes.split(","), "publisher": cols[4]})
    return rows


def collect_flatpaks() -> list[dict]:
    out = _run(["flatpak", "list", "--app", "--columns=application,origin"], 30)
    rows = []
    for line in out.splitlines():
        cols = line.split("\t") if "\t" in line else line.split()
        if len(cols) >= 1 and FLATPAK_ID_RE.match(cols[0]):
            rows.append({"id": cols[0], "origin": cols[1] if len(cols) > 1 else ""})
    return rows


def third_party_repos(apt_rows: list[dict]) -> list[dict]:
    """The repository definitions the third-party apps came from (credentials removed)."""
    hosts = {r["host"] for r in apt_rows if r["origin"] == "third_party" and r["host"]}
    repos = []
    for entry in ui.read_apt_sources(ui._apt_root()):
        host = urlsplit(entry["uri"]).hostname or ""
        if host in hosts:
            repos.append({"file": entry.get("file"), "uri": redact(entry["uri"]), "suites": entry.get("suites", []), "host": host})
    return repos


def distro() -> dict:
    try:
        data = ui.parse_os_release(ui._os_release_path().read_text())
    except OSError:
        data = {}
    return {"id": data.get("ID", ""), "version": data.get("VERSION_ID", ""), "codename": ui.current_codename(),
            "arch": ui._native_arch()}


def build_manifest() -> dict:
    d = distro()
    apt = collect_apt(d["arch"])
    return {
        "schema": SCHEMA,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "source_machine": socket.gethostname(),
        "distro": d,
        "apt": apt,
        "snaps": collect_snaps(),
        "flatpaks": collect_flatpaks(),
        "third_party_repos": third_party_repos(apt),
        "holds": sorted(ui.held_packages(d["arch"])),
    }


# --------------------------------------------------------------------- planning
def validate_manifest(m: object) -> str | None:
    """None if usable, otherwise why not. Never trusts the file: names are checked against strict patterns."""
    if not isinstance(m, dict) or m.get("schema") != SCHEMA:
        return "This isn't a LinuxGuardian app list (or it is from a newer version)."
    if not isinstance(m.get("distro"), dict) or not isinstance(m.get("apt"), list) or not isinstance(m.get("snaps"), list):
        return "The app list is incomplete."
    return None


def compatibility(m: dict, here: dict | None = None) -> tuple[bool, str]:
    here = here or distro()
    src = m["distro"]
    if src.get("id") != here.get("id") or src.get("version") != here.get("version"):
        return False, (f"This list is from {src.get('id')} {src.get('version')} but this laptop runs "
                       f"{here.get('id')} {here.get('version')}. Packages differ between releases, so nothing will be installed.")
    if src.get("arch") != here.get("arch"):
        return False, f"This list is for {src.get('arch')} but this laptop is {here.get('arch')}."
    return True, ""


def make_plan(m: dict) -> dict:
    here = distro()
    ok, why = compatibility(m, here)
    plan = {"compatible": ok, "reason": why, "source": m.get("source_machine"), "created": m.get("created"),
            "apt": {"install": [], "have": [], "hardware": [], "needs_repo": [], "unavailable": [], "invalid": []},
            "snaps": {"install": [], "install_classic": [], "have": [], "invalid": []},
            "flatpaks": [r for r in m.get("flatpaks", []) if isinstance(r, dict) and FLATPAK_ID_RE.match(str(r.get("id", "")))],
            "repos": m.get("third_party_repos", []) if isinstance(m.get("third_party_repos"), list) else []}
    installed = {ui.normalize_pkg(n, here["arch"]) for n in ui.installed_packages()}
    snaps_here = {r["name"] for r in collect_snaps()} | {r.split()[0] for r in _run(["snap", "list"], 30).splitlines()[1:] if r.split()}
    my_hosts = {urlsplit(e["uri"]).hostname or "" for e in ui.read_apt_sources(ui._apt_root())}

    candidates = []
    for row in m["apt"]:
        name = str(row.get("name", "")) if isinstance(row, dict) else ""
        if not ui.PACKAGE_NAME_RE.match(name):
            plan["apt"]["invalid"].append(name[:60])
        elif name in installed:
            plan["apt"]["have"].append(name)
        elif row.get("hardware_specific") or HARDWARE_RE.match(name):
            plan["apt"]["hardware"].append(name)
        elif row.get("origin") == "third_party" and row.get("host") not in my_hosts:
            plan["apt"]["needs_repo"].append({"name": name, "host": row.get("host")})
        elif row.get("origin") == "local":
            plan["apt"]["unavailable"].append({"name": name, "why": "was installed from a downloaded .deb file"})
        else:
            candidates.append(name)
    if candidates:
        pol = {}
        for i in range(0, len(candidates), 80):
            pol.update(parse_policy(_run(["apt-cache", "policy", *candidates[i : i + 80]], 120)))
        for name in candidates:
            if pol.get(name, {}).get("candidate"):
                plan["apt"]["install"].append(name)
            else:
                plan["apt"]["unavailable"].append({"name": name, "why": "not available from this laptop's package sources"})
    for row in m["snaps"]:
        name = str(row.get("name", "")) if isinstance(row, dict) else ""
        if not SNAP_NAME_RE.match(name):
            plan["snaps"]["invalid"].append(name[:60])
        elif name in snaps_here:
            plan["snaps"]["have"].append(name)
        elif row.get("classic"):
            plan["snaps"]["install_classic"].append(name)
        else:
            plan["snaps"]["install"].append(name)
    if not ok:                              # a mismatched release installs nothing, whatever else is true
        for k in ("install",):
            plan["apt"][k] = []
        plan["snaps"]["install"] = []
        plan["snaps"]["install_classic"] = []
    return plan


def installable_names(m: dict, kind: str) -> list[str]:
    """The only names the installer may be given. Recomputed from the plan on THIS machine."""
    plan = make_plan(m)
    if not plan["compatible"]:
        return []
    return {"apt": plan["apt"]["install"], "snap": plan["snaps"]["install"],
            "snap-classic": plan["snaps"]["install_classic"]}[kind]


def render_plan(plan: dict) -> str:
    lines = []
    if not plan["compatible"]:
        return plan["reason"]
    a, s = plan["apt"], plan["snaps"]
    lines.append(f"From {plan['source']}. On this laptop:")
    lines.append(f"  {len(a['install'])} Ubuntu apps to install, {len(a['have'])} already here")
    lines.append(f"  {len(s['install'])} snaps to install ({len(s['install_classic'])} more are classic/unconfined), {len(s['have'])} already here")
    lines.append(f"  {len(a['needs_repo'])} need a third-party repository you'd add yourself")
    lines.append(f"  {len(a['hardware'])} hardware-specific packages skipped on purpose")
    lines.append(f"  {len(a['unavailable'])} not available here")
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--export", nargs="?", const="-", metavar="FILE")
    g.add_argument("--plan", metavar="FILE")
    g.add_argument("--names", metavar="FILE")
    p.add_argument("--kind", choices=("apt", "snap", "snap-classic"))
    p.add_argument("--json", action="store_true")
    a = p.parse_args()
    if a.export is not None:
        text = json.dumps(build_manifest(), indent=2)
        if a.export == "-":
            print(text)
        else:
            path = Path(a.export).expanduser()
            path.write_text(text + "\n")
            os.chmod(path, 0o600)
            print(f"Wrote {path}")
        return 0
    try:
        manifest = json.loads(Path(a.plan or a.names).expanduser().read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Can't read that file: {exc}", file=sys.stderr)
        return 1
    problem = validate_manifest(manifest)
    if problem:
        print(problem, file=sys.stderr)
        return 1
    if a.names:
        if not a.kind:
            p.error("--names needs --kind")
        print("\n".join(installable_names(manifest, a.kind)))
        return 0
    plan = make_plan(manifest)
    print(json.dumps(plan) if a.json else render_plan(plan))
    return 0 if plan["compatible"] else 3


if __name__ == "__main__":
    sys.exit(main())

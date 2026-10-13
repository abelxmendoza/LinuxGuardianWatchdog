#!/usr/bin/env python3
"""Programs that always run with someone else's rights (setuid / setgid), and a new one appearing.  (read-only, no root)

A setuid program runs as its OWNER whoever starts it. `sudo`, `passwd` and `mount` are meant to be like that. An attacker who
has a way in but not administrator rights looks for a setuid program they can abuse, and one who gets administrator rights
often leaves a setuid copy of a shell behind as a way back. So:

  * a baseline of every setuid/setgid file is taken the first time, and again from time to time
  * a NEW one is reported: critical in places programs never legitimately live (/tmp, your home, anything not owned by root),
    a warning in the system folders when no package owns it, information when a package installed it
  * a known one whose contents changed without a package explaining it is a warning

Looking walks the disk, so it runs at most every six hours, stays within one filesystem at a time, skips folders that are huge
and harmless (caches, node_modules, .git), and gives up after a time limit without treating unseen files as removed.

  setuid_watch.py --check [--json]    look now (the live monitor does this every six hours)
  setuid_watch.py --list              the setuid/setgid programs found at the last look

Test hooks: LG_HOME, LG_SETUID_ROOTS (colon-separated folders to walk), LG_SETUID_NOW (or LG_SENSOR_NOW).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

INTERVAL = 6 * 3600
TIME_LIMIT = 90
DEFAULT_ROOTS = ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/var", "/srv", "/tmp", "/dev/shm", "/home", "/root"]
SKIP_NAMES = {".cache", "node_modules", ".git", ".npm", ".cargo", ".rustup", ".gradle", ".m2", "__pycache__", ".venv", "venv", "snap", ".conda", ".steam"}
SKIP_PREFIXES = ("/proc", "/sys", "/dev", "/run")
UNSAFE_PLACES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/", "/var/lib/docker/")
SYSTEM_PLACES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/")


def now() -> float:
    return float(os.environ.get("LG_SETUID_NOW") or os.environ.get("LG_SENSOR_NOW") or time.time())


def roots() -> list[str]:
    """Folders to walk, with symlinks resolved and duplicates dropped (on a merged-/usr system /bin IS /usr/bin)."""
    env = os.environ.get("LG_SETUID_ROOTS")
    out: list[str] = []
    for r in ([x for x in env.split(":") if x] if env is not None else DEFAULT_ROOTS):
        real = os.path.realpath(r)
        if os.path.isdir(real) and real not in out:
            out.append(real)
    return out


def package_owner(path: str) -> str:
    try:
        r = subprocess.run(["dpkg", "-S", "--", path], capture_output=True, text=True, timeout=10, check=False, env=dict(os.environ, LC_ALL="C"))
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return r.stdout.split(":")[0].strip() if r.returncode == 0 and ": " in r.stdout else ""


def _sha(path: str) -> str:
    h = hashlib.sha256()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)      # never block on a pipe, never follow a swapped-in link
        with os.fdopen(fd, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()[:20]


def scan(deadline: float | None = None) -> tuple[dict[str, dict], bool]:
    """Walk the roots. Returns ({path: {mode, uid, sha}}, complete). Never follows symlinks or crosses into another filesystem."""
    found: dict[str, dict] = {}
    complete = True
    stop = (time.monotonic() + TIME_LIMIT) if deadline is None else deadline
    for top in roots():
        try:
            top_dev = os.lstat(top).st_dev
        except OSError:
            continue
        for dirpath, dirnames, filenames in os.walk(top, followlinks=False):
            if time.monotonic() > stop:
                return found, False
            if dirpath.startswith(SKIP_PREFIXES):
                dirnames[:] = []
                continue
            keep = []
            for d in dirnames:
                full = os.path.join(dirpath, d)
                if d in SKIP_NAMES or full.startswith(SKIP_PREFIXES):
                    continue
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if stat.S_ISDIR(st.st_mode) and st.st_dev == top_dev:      # one filesystem at a time
                    keep.append(d)
            dirnames[:] = keep
            for name in filenames:
                full = os.path.join(dirpath, name)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    found[full] = {"mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid, "sha": _sha(full)}
    return found, complete


def _f(key: str, severity: str, event: str, message: str, path: str) -> dict:
    return {"key": key, "severity": severity, "event": event, "message": message, "entity": [path], "technique": "T1548.001", "stage": "privilege",
            "extra": {"path": path}}


def describe(info: dict) -> str:
    bits = []
    if info["mode"] & stat.S_ISUID:
        bits.append("setuid")
    if info["mode"] & stat.S_ISGID:
        bits.append("setgid")
    owner = "root" if info["uid"] == 0 else f"user id {info['uid']}"
    return f"{'/'.join(bits)}, owned by {owner}"


def allowed(path: str, allow: list[str]) -> bool:
    """The same 'this is expected' rule the other sensors use: an exact path, or a folder written with a trailing slash."""
    return any(path == a or (a.endswith("/") and path.startswith(a)) for a in allow)


def diff(old: dict[str, dict] | None, new: dict[str, dict], allow: list[str] | None = None) -> list[dict]:
    if old is None:
        return []
    out: list[dict] = []
    for path, info in new.items():
        if allow and allowed(path, allow):
            continue
        before = old.get(path)
        if before is None:
            owner_pkg = package_owner(path) if path.startswith(SYSTEM_PLACES) else ""
            if path.startswith(UNSAFE_PLACES) or (info["uid"] != 0 and not owner_pkg):
                out.append(_f(f"su:new:{path}:{info['sha']}", "critical", "setuid_new",
                              f"A program that runs with elevated rights appeared in a place programs shouldn't live, or under an unexpected owner: {path} "
                              f"({describe(info)}). Attackers leave these behind as a way back to administrator rights.", path))
            elif owner_pkg:
                out.append(_f(f"su:new:{path}:{info['sha']}", "info", "setuid_new", f"A new {describe(info)} program was installed by the package {owner_pkg}: {path}.", path))
            else:
                out.append(_f(f"su:new:{path}:{info['sha']}", "warning", "setuid_new",
                              f"A new program that runs with elevated rights appeared and no package owns it: {path} ({describe(info)}).", path))
        elif before.get("sha") and info["sha"] and before["sha"] != info["sha"]:
            owner_pkg = package_owner(path) if path.startswith(SYSTEM_PLACES) else ""
            sev = "info" if owner_pkg else "warning"
            out.append(_f(f"su:mod:{path}:{info['sha']}", sev, "setuid_changed",
                          f"The contents of {path} ({describe(info)}) changed" + (f" (owned by the package {owner_pkg}, so probably an update)." if owner_pkg
                                                                                else " and no package explains it."), path))
    return out


def run(state: dict, force: bool = False, allow: list[str] | None = None) -> list[dict]:
    """One look if it is due. Updates `state['setuid']`. The first look only learns."""
    block = state.get("setuid")
    t = now()
    if block and not force and t - block.get("last", 0) < INTERVAL:
        return []
    found, complete = scan()
    old = block["files"] if block else None
    findings = diff(old, found, allow)
    if old is not None and not complete:
        # a partial look can't say anything is gone; keep what we knew about the rest and add what we saw
        found = {**old, **found}
    state["setuid"] = {"files": found, "last": t, "complete": complete}
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--list", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    import sensors

    state = sensors.load_state()
    if a.list:
        files = (state.get("setuid") or {}).get("files", {})
        for p, i in sorted(files.items()):
            print(f"{p}  ({describe(i)})")
        if not files:
            print("No look has been taken yet: run --check.")
        return 0
    first = "setuid" not in state
    findings = run(state, force=True)
    sensors.save_state(state)
    n = len(state["setuid"]["files"])
    if a.json:
        print(json.dumps({"first_look": first, "count": n, "findings": findings, "complete": state["setuid"]["complete"]}))
    elif first:
        print(f"First look: recorded {n} setuid/setgid programs as normal. New ones will be reported.")
    else:
        print(f"{n} setuid/setgid programs." + ("" if state["setuid"]["complete"] else " (The look ran out of time and was partial.)"))
        for f in findings:
            print(f"[{f['severity']}] {f['message']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

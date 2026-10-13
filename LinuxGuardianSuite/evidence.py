#!/usr/bin/env python3
"""Collect a read-only evidence bundle for an incident, so you can investigate (or hand it to someone) without guessing.

  evidence.py --incident ID [--out DIR]

Writes a private folder (mode 700, files 600) under ~/.linuxguardian/evidence/ containing: the incident story, the
process tree, network connections, recent logins, startup entries, and for each implicated program its path, owner
package, hash and (if still running) its parent chain. It never copies your documents, never reads process environments
(they hold secrets), and scrubs tokens and passwords out of command lines.

Test hooks: LG_HOME, LG_PROC, LG_AUTH_LOG.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import time
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

import incidents  # noqa: E402
import sensors  # noqa: E402
from events import lg_home  # noqa: E402


def run(cmd: list[str], timeout: float = 15, limit: int = 60_000) -> str:
    env = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False)
        return (p.stdout + (p.stderr if not p.stdout else ""))[:limit]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"(could not run {' '.join(cmd)}: {exc})"


def sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return "(unreadable)"


def parent_chain(pid: int) -> list[str]:
    proc = Path(os.environ.get("LG_PROC", "/proc"))
    chain, seen = [], set()
    while pid > 1 and pid not in seen:
        seen.add(pid)
        try:
            stat = (proc / str(pid) / "stat").read_text()
            comm = re.search(r"\((.*)\)", stat).group(1)
            ppid = int(stat.rsplit(")", 1)[1].split()[1])
            chain.append(f"{pid} {comm}")
            pid = ppid
        except (OSError, AttributeError, ValueError, IndexError):
            break
    return chain


def write(d: Path, name: str, text: str) -> None:
    p = d / name
    p.write_text(text)
    os.chmod(p, 0o600)


def sections(inc: incidents.Incident) -> dict[str, str]:
    """The evidence as {file name: text}. Pure collection, nothing is written, so other readers (the AI investigator)
    see exactly the same facts the saved bundle contains."""
    out: dict[str, str] = {"00-incident.txt": incidents.narrative(inc) + "\n"}
    out["01-processes.txt"] = sensors.redact_args(run(["ps", "-eo", "pid,ppid,user,etime,args", "--forest"]))
    out["02-network.txt"] = sensors.redact_args(run(["ss", "-tunap"]))
    out["03-logins.txt"] = run(["last", "-n", "25", "-F"]) + "\n--- who ---\n" + run(["who"])
    auth = Path(os.environ.get("LG_AUTH_LOG", "/var/log/auth.log"))
    needles = [e for e in inc.entities if len(e) > 2]
    try:
        lines = auth.read_text(errors="replace").splitlines()[-4000:]
        pick = [sensors.redact_args(l) for l in lines if any(n in l for n in needles)] or [sensors.redact_args(l) for l in lines[-60:]]
        out["04-auth-log-excerpt.txt"] = "\n".join(pick[-200:]) + "\n"
    except OSError:
        out["04-auth-log-excerpt.txt"] = "(auth log not readable: join the 'adm' group)\n"
    snap = sensors.autorun_files()
    out["05-startup-entries.txt"] = "\n".join(f"{v or '-':16}  {k}" for k, v in sorted(snap.items())) + "\n"
    parts = []
    for exe in inc.exes:
        owner = sensors.package_owner(exe)
        try:
            st = os.stat(exe)
            meta = f"size {st.st_size}, modified {time.strftime('%Y-%m-%d %H:%M', time.localtime(st.st_mtime))}, mode {oct(st.st_mode & 0o7777)}"
        except OSError:
            meta = "file no longer exists"
        parts.append(f"{exe}\n  package: {owner or 'NONE (not installed by apt)'}\n  {meta}\n  sha256: {sha256(exe)}")
    for pid in inc.pids:
        chain = parent_chain(pid)
        parts.append(f"pid {pid}: " + (" <- ".join(chain) if chain else "(no longer running)"))
    out["06-implicated-programs.txt"] = "\n\n".join(parts) + "\n" if parts else "(no specific program was involved)\n"
    out["07-user-services.txt"] = run(["systemctl", "--user", "list-units", "--type=service", "--state=running", "--no-pager"])
    return out


def collect(inc: incidents.Incident, out_dir: Path | None = None) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    d = out_dir or (lg_home() / "evidence" / f"{inc.id}-{stamp}")
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    for name, text in sections(inc).items():
        write(d, name, text)
    write(d, "README.txt", "Read-only evidence bundle made by LinuxGuardian Watchdog. Nothing here was changed on your system.\n"
                           "Command lines are scrubbed of tokens and passwords; process environments and your documents are never collected.\n")
    return d


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--incident", required=True)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()
    found = [i for i in incidents.build(days=30, include_acknowledged=True) if i.id == a.incident]
    if not found:
        print("No such incident (it may have aged out).", file=sys.stderr)
        return 1
    print(collect(found[0], a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())

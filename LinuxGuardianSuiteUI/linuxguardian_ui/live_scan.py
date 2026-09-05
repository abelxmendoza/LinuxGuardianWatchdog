"""Discover and sample an already-running suite scan via /proc.

Used so the GUI can show progress for a ClamAV process that was started
before this window opened (or before live progress existed).
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import time

_SKIP_NAMES = {
    "clamscan",
    "rkhunter",
    "tee",
    "stdbuf",
    "tr",
    "bash",
    "dash",
    "sh",
    "python3",
    "python",
}
_SKIP_PREFIXES = (
    "/dev/",
    "/proc/",
    "/sys/",
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/lib/",
    "/usr/lib64/",
    "/lib/",
    "/lib64/",
    "/etc/",
    "/run/",
)
_SKIP_SUFFIXES = (".so", ".so.11", ".so.9")


@dataclass
class RunningScan:
    pid: int
    comm: str
    phase: str
    script_pid: int | None
    start_epoch: float
    cmdline: str
    target: str


@dataclass
class ScanSnapshot:
    pid: int
    phase: str
    comm: str
    elapsed_sec: float
    current: str
    bytes_read: int
    cpu_pct: str
    alive: bool
    target: str


def find_running_scan() -> RunningScan | None:
    """Return the most relevant in-flight scanner, if any."""
    clam = _find_by_comm("clamscan")
    if clam:
        return clam
    rkh = _find_by_comm("rkhunter")
    if rkh:
        return rkh
    return _find_script("linux_guardian.sh") or _find_script("linux_watchdog.sh")


def snapshot(scan: RunningScan) -> ScanSnapshot:
    if not Path(f"/proc/{scan.pid}").exists():
        # Script may still be alive after clamscan exited (next phase).
        nxt = find_running_scan()
        if nxt is None:
            return ScanSnapshot(
                pid=scan.pid,
                phase=scan.phase,
                comm=scan.comm,
                elapsed_sec=max(0.0, time.time() - scan.start_epoch),
                current="",
                bytes_read=0,
                cpu_pct="0",
                alive=False,
                target=scan.target,
            )
        scan.pid = nxt.pid
        scan.comm = nxt.comm
        scan.phase = nxt.phase
        scan.script_pid = nxt.script_pid
        scan.cmdline = nxt.cmdline
        scan.target = nxt.target
        scan.start_epoch = nxt.start_epoch
    elapsed = max(0.0, time.time() - scan.start_epoch)
    return ScanSnapshot(
        pid=scan.pid,
        phase=scan.phase,
        comm=scan.comm,
        elapsed_sec=elapsed,
        current=_current_path(scan.pid) or scan.target,
        bytes_read=_read_bytes(scan.pid),
        cpu_pct=_lifetime_cpu_pct(scan.pid, elapsed),
        alive=True,
        target=scan.target,
    )


def human_bytes(n: int) -> str:
    size = float(max(0, n))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _find_by_comm(comm: str) -> RunningScan | None:
    for pid in _pids():
        if _comm(pid) != comm:
            continue
        cmdline = _cmdline(pid)
        phase = "clamav" if comm == "clamscan" else "rkhunter"
        target = _target_from_cmdline(cmdline)
        script_pid = _parent_script(pid)
        return RunningScan(
            pid=pid,
            comm=comm,
            phase=phase,
            script_pid=script_pid,
            start_epoch=_start_epoch(pid),
            cmdline=cmdline,
            target=target,
        )
    return None


def _find_script(name: str) -> RunningScan | None:
    for pid in _pids():
        cmdline = _cmdline(pid)
        if f"/{name}" not in cmdline and not cmdline.endswith(name):
            continue
        if any(token in cmdline for token in ("pgrep", "grep -", "/grep ")):
            continue
        phase = "integrity" if "watchdog" in name else "clamav"
        return RunningScan(
            pid=pid,
            comm=_comm(pid),
            phase=phase,
            script_pid=pid,
            start_epoch=_start_epoch(pid),
            cmdline=cmdline,
            target=_target_from_cmdline(cmdline),
        )
    return None


def _pids() -> list[int]:
    out: list[int] = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            out.append(int(entry.name))
    return out


def _comm(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/comm").read_text().strip()
    except OSError:
        return ""


def _cmdline(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except OSError:
        return ""


def _parent_script(pid: int) -> int | None:
    try:
        status = Path(f"/proc/{pid}/status").read_text()
    except OSError:
        return None
    ppid = 0
    for line in status.splitlines():
        if line.startswith("PPid:"):
            ppid = int(line.split()[1])
            break
    if ppid and "linux_guardian.sh" in _cmdline(ppid):
        return ppid
    return None


def _target_from_cmdline(cmdline: str) -> str:
    parts = cmdline.split()
    home = str(Path.home())
    for part in reversed(parts):
        if part.startswith("/") and part not in ("--exclude-dir=^/sys|^/proc",):
            if part.endswith(".sh"):
                continue
            return part
    if "--scan" in parts:
        return home
    return home


def _start_epoch(pid: int) -> float:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        # comm can contain spaces/parens; starttime is field 22 of the
        # space-separated tail after the last ')'.
        tail = stat.rsplit(")", 1)[1].split()
        start_ticks = int(tail[19])  # field 22 overall, 20 after the ')'
        clk = os.sysconf("SC_CLK_TCK") or 100
        btime = 0
        for line in Path("/proc/stat").read_text().splitlines():
            if line.startswith("btime "):
                btime = int(line.split()[1])
                break
        return btime + (start_ticks / clk)
    except (OSError, IndexError, ValueError):
        return time.time()


def _read_bytes(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/io").read_text().splitlines():
            if line.startswith("read_bytes:"):
                return int(line.split()[1])
    except OSError:
        return 0
    return 0


def _lifetime_cpu_pct(pid: int, elapsed: float) -> str:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        tail = stat.rsplit(")", 1)[1].split()
        utime = int(tail[11])
        stime = int(tail[12])
        clk = os.sysconf("SC_CLK_TCK") or 100
        cpu_sec = (utime + stime) / clk
        if elapsed <= 0:
            return "0%"
        return f"{min(999, cpu_sec / elapsed * 100):.0f}%"
    except (OSError, IndexError, ValueError):
        return "?"


def _current_path(pid: int) -> str:
    fd_dir = Path(f"/proc/{pid}/fd")
    if not fd_dir.is_dir():
        return ""
    candidates: list[str] = []
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = ""
    try:
        entries = list(fd_dir.iterdir())
    except OSError:
        return ""
    for fd in entries:
        try:
            target = os.readlink(fd)
        except OSError:
            continue
        if target == exe:
            continue
        if target.startswith("socket:") or target.startswith("pipe:") or target.startswith("anon_inode:"):
            continue
        if any(target.startswith(p) for p in _SKIP_PREFIXES):
            continue
        base = Path(target).name
        if base in _SKIP_NAMES:
            continue
        if any(target.endswith(s) for s in (".cvd", ".cld", ".cud")):
            return target  # signature load
        if Path(target).is_file() or Path(target).is_dir():
            candidates.append(target)
    if not candidates:
        return ""
    home = str(Path.home())
    homed = [c for c in candidates if c.startswith(home)]
    pool = homed or candidates
    return max(pool, key=len)

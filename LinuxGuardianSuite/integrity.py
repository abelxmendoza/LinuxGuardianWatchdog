#!/usr/bin/env python3
"""File-integrity baseline + honeypot. The engine behind linux_watchdog.sh.

What it watches (see `roots()`): ~/Documents, plus the places malware uses to survive a reboot
or hide: shell start-up files, ~/.ssh, autostart entries, user systemd units, /etc/ld.so.preload
(the classic rootkit hook), /etc/passwd and friends. Caches, `node_modules` and the honeypot itself are
skipped: they change constantly and reading the honeypot to hash it would trip its own alarm.

Your own software projects are skipped too: anything inside a git working tree changes every time you
work, and git already records exactly what changed. What attackers use in a repository is NOT skipped:
`.git/hooks` and `.git/config` (hooks run on commit; the config can name a program to run) stay watched.

How loud a change is depends on where it is. A change where programs start from is a warning. Editing
your own documents is routine information, unless MANY change at once (a burst, the shape of ransomware),
which is a warning.

Changes are classified as MODIFIED, NEW or MISSING. The honeypot is checked with `stat` only (never
read), and an access is reported once, not on every later check.

  integrity.py --init | --check | --status | --roots
  integrity.py --accept PATH... | --forget PATH...   (used by the installer for LinuxGuardian's own timers)

A baseline is a record of "this is how it should look". After you change watched files on purpose,
run --init to accept the new state; until then the changes keep being reported.

Test hooks: LG_HOME, LG_INTEGRITY_ROOTS (colon-separated), LG_HONEYPOT_DIR, LG_INTEGRITY_HOME (stand-in for $HOME).
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

from events import lg_home, record_event  # noqa: E402

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".cache", ".venv", "venv", ".mypy_cache", ".pytest_cache"}
MAX_EVENTS = 20           # per check; beyond this one summary event is written
BURST = 10                # this many ordinary documents changing in one check is not editing, it is something happening to them
GIT_ALWAYS_WATCHED = ("hooks", "config")     # inside .git: hooks run on commit, config can name a program to run


def home() -> Path:
    return Path(os.environ.get("LG_INTEGRITY_HOME", str(Path.home())))


def honeypot_dir() -> Path:
    return Path(os.environ.get("LG_HONEYPOT_DIR", str(home() / "Documents" / "Passwords_DO_NOT_OPEN")))


def baseline_dir() -> Path:
    return lg_home() / "baselines"


def baseline_file() -> Path:
    return baseline_dir() / "baseline.sha256"


def meta_file() -> Path:
    return baseline_dir() / "baseline.meta.json"


def legacy_baseline() -> Path:
    return baseline_dir() / "documents.sha256"


def roots() -> list[Path]:
    override = os.environ.get("LG_INTEGRITY_ROOTS")
    if override is not None:
        return [Path(p) for p in override.split(":") if p]
    h = home()
    candidates = [
        h / "Documents",
        h / ".bashrc", h / ".bash_profile", h / ".bash_login", h / ".profile", h / ".zshrc", h / ".zprofile",
        h / ".xprofile", h / ".xsessionrc", h / ".pam_environment",
        h / ".ssh",
        h / ".config" / "autostart",
        h / ".config" / "systemd" / "user",
        h / ".config" / "environment.d",
        Path("/etc/ld.so.preload"), Path("/etc/passwd"), Path("/etc/group"), Path("/etc/hosts"),
        Path("/etc/crontab"), Path("/etc/ssh/sshd_config"),
    ]
    return [p for p in candidates if p.exists()]


def decoy_files() -> set[Path]:
    """Planted decoy secrets: reading one to hash it would look exactly like someone stealing it, so they are never opened here."""
    try:
        import decoys

        return set(decoys.paths(home()))
    except Exception:  # noqa: BLE001 - integrity must work without the decoy module
        return set()


_SKIP_ALWAYS = SKIP_DIRS - {".git"}


@functools.lru_cache(maxsize=8192)
def _is_repo_root(directory: str) -> bool:
    return os.path.isdir(os.path.join(directory, ".git"))


def in_git_worktree(path: Path) -> bool:
    """Is this inside a software project's git working tree, other than the few parts of .git that stay watched?"""
    for parent in path.parents:
        if _is_repo_root(str(parent)):
            parts = path.relative_to(parent).parts
            if parts[0] != ".git":
                return True
            return not (len(parts) >= 2 and parts[1] in GIT_ALWAYS_WATCHED and (parts[1] == "hooks" or len(parts) == 2) and not path.name.endswith(".sample"))
    return False


def excluded(path: str) -> bool:
    """Would `iter_files` have skipped this path? (Also used to ignore baseline entries from places that are no longer watched.)"""
    p = Path(path)
    hp = honeypot_dir()
    return (any(part in _SKIP_ALWAYS for part in p.parts) or p == hp or hp in p.parents or p in decoy_files()
            or in_git_worktree(p))


def iter_files(root_list: list[Path]):
    hp = honeypot_dir()
    decoys = decoy_files()
    for root in root_list:
        if root in decoys:
            continue
        if root.is_file() or root.is_symlink():
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            here = Path(dirpath)
            if here.name == ".git" and _is_repo_root(str(here.parent)):
                dirnames[:] = [d for d in dirnames if d == "hooks"]             # only what attackers use: hooks and config
                filenames = [f for f in filenames if f == "config"]
            elif here.parent.name == ".git" and here.name == "hooks":
                filenames = [f for f in filenames if not f.endswith(".sample")]
            elif _is_repo_root(str(here)):
                dirnames[:] = [d for d in dirnames if d == ".git"]              # a software project: git already tracks it
                filenames = []
            else:
                dirnames[:] = [d for d in dirnames if d not in _SKIP_ALWAYS and here / d != hp]
            for name in filenames:
                path = here / name
                if path.is_symlink() or path in decoys:
                    continue
                yield path


def sha256(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def progress(message: str, **kv: object) -> None:
    extras = "".join(f"|{k}={v}" for k, v in kv.items())
    print(f"LG_PROGRESS|phase=integrity|message={message}{extras}", flush=True)


def snapshot(root_list: list[Path], verb: str) -> dict[str, str]:
    """{path: sha256} for every readable file; prints progress as it goes."""
    files = [str(p) for p in iter_files(root_list)]
    total = len(files)
    result: dict[str, str] = {}
    started = time.time()
    done = 0
    last = 0.0
    with ThreadPoolExecutor(max_workers=max(2, (os.cpu_count() or 2))) as pool:
        for path, digest in zip(files, pool.map(lambda f: sha256(Path(f)), files)):
            done += 1
            if digest is not None:
                result[path] = digest
            now = time.time()
            if now - last >= 1.0:
                last = now
                elapsed = int(now - started)
                pct = min(99, done * 100 // total) if total else 99
                progress(f"{verb} {done} of {total} files", done=done, total=total, pct=pct, elapsed_sec=elapsed)
    return result


def honeypot_state() -> dict | None:
    f = honeypot_dir() / "passwords.txt"
    try:
        st = f.stat()          # stat never reads the file, so it can't set off the alarm itself
    except OSError:
        return None
    return {"atime": int(st.st_atime), "mtime": int(st.st_mtime), "size": st.st_size}


def ensure_honeypot() -> None:
    d = honeypot_dir()
    f = d / "passwords.txt"
    if f.exists():
        return
    d.mkdir(parents=True, exist_ok=True)
    f.write_text(
        "This is a decoy file created by LinuxGuardian Watchdog.\n"
        "If you did not create this file and did not expect to see it opened,\n"
        "something on this machine accessed it without authorization.\n"
    )
    print(f"[INFO] Honeypot created at {d}")


def write_baseline(snap: dict[str, str], root_list: list[Path]) -> None:
    baseline_dir().mkdir(parents=True, exist_ok=True)
    tmp = baseline_file().with_suffix(".tmp")
    tmp.write_text("".join(f"{h}  {p}\n" for p, h in sorted(snap.items())))
    tmp.replace(baseline_file())
    meta = {"created_epoch": int(time.time()), "roots": [str(r) for r in root_list], "files": len(snap),
            "honeypot": honeypot_state()}
    meta_file().write_text(json.dumps(meta))


def read_baseline() -> dict[str, str] | None:
    path = baseline_file() if baseline_file().is_file() else legacy_baseline()
    if not path.is_file():
        return None
    out: dict[str, str] = {}
    for line in path.read_text(errors="replace").splitlines():
        digest, sep, name = line.partition("  ")
        if sep and len(digest) == 64:
            out[name] = digest
    return out


def read_meta() -> dict:
    try:
        data = json.loads(meta_file().read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def diff(old: dict[str, str], new: dict[str, str]) -> dict[str, list[str]]:
    return {
        "modified": sorted(p for p in new if p in old and new[p] != old[p]),
        "new": sorted(p for p in new if p not in old),
        "missing": sorted(p for p in old if p not in new),
    }


def do_init() -> int:
    _is_repo_root.cache_clear()
    rs = roots()
    ensure_honeypot()
    print(f"[INFO] Building integrity baseline for {len(rs)} locations:")
    for r in rs:
        print(f"    {r}")
    snap = snapshot(rs, "Hashed")
    write_baseline(snap, rs)
    progress("Baseline complete", pct=100, done=len(snap), total=len(snap))
    print(f"[ OK ] Baseline written ({len(snap)} files)")
    return 0


def do_check() -> int:
    _is_repo_root.cache_clear()
    old = read_baseline()
    if old is None:
        print("[FAIL] No baseline found. Run with --init first.", file=sys.stderr)
        return 1
    rs = roots()
    meta = read_meta()
    built_for = meta.get("roots")
    if built_for is None:
        # Baseline from before extra locations and exclusions existed (Documents only, .git and the
        # honeypot included). Compare like with like instead of flooding "missing" for skipped files.
        print("[INFO] This baseline predates the extra watched locations; rebuild it with --init to cover them.")
    ensure_honeypot()
    progress("Hashing files for comparison", pct=0, total=len(old))
    current = snapshot(rs, "Hashed")
    if built_for is None:
        docs = str(home() / "Documents") + os.sep
        old = {p: h for p, h in old.items() if p.startswith(docs) and not excluded(p)}
        current = {p: h for p, h in current.items() if p.startswith(docs)}
    old = {p: h for p, h in old.items() if not excluded(p)}     # compare like with like: places no longer watched aren't "missing"
    changes = diff(old, current)
    any_change = False
    recorded = 0
    docs_prefix = str(home() / "Documents") + os.sep
    # A new file in Documents is routine. A new file where programs start from (autostart, shell
    # start-up, ssh keys, user services, /etc hooks) is exactly what persistence looks like.
    def _starts_programs(p: str) -> bool:
        return not p.startswith(docs_prefix) or os.sep + ".git" + os.sep in p        # a new git hook runs a program on commit: it is persistence

    changes["new_persistence"] = [p for p in changes["new"] if _starts_programs(p)]
    changes["new"] = [p for p in changes["new"] if not _starts_programs(p)]
    # Editing your own documents is routine. Where programs start from is not. And many documents changing at once is not editing.
    docs_changed = [p for k in ("modified", "missing") for p in changes[k] if p.startswith(docs_prefix) and os.sep + ".git" + os.sep not in p]
    burst = len(docs_changed) >= BURST

    def severity(kind: str, path: str) -> str:
        if kind == "new":
            return "info"
        if os.sep + ".git" + os.sep in path:
            return "warning"                 # a git hook or config changed: that runs programs, it isn't a document
        return "info" if path.startswith(docs_prefix) and not burst else "warning"

    for kind, label in (("modified", "File changed"), ("missing", "File missing"),
                        ("new_persistence", "New file in a start-up/persistence location"), ("new", "New file")):
        paths = changes[kind]
        if not paths:
            continue
        loud = any(severity(kind, p) == "warning" for p in paths)
        any_change = any_change or (kind != "new" and loud)
        heading = {"modified": "Modified files", "missing": "Missing files (in the baseline, gone now)",
                   "new_persistence": "New files in start-up/persistence locations",
                   "new": "New files in Documents since the baseline"}[kind]
        if not loud and kind != "new":
            heading += " (your own documents, routine edits)"
        print(f"[{'WARN' if loud else 'INFO'}] {heading}: {len(paths)}")
        for p in paths[:50]:
            print(f"    {p}")
        if len(paths) > 50:
            print(f"    …and {len(paths) - 50} more")
        for p in paths:
            if recorded >= MAX_EVENTS:
                break
            if kind == "new":
                continue                     # new files are information, not alarms
            record_event("integrity", severity(kind, p), "file_" + kind, f"{label}: {p}", path=p)
            recorded += 1
    flagged = sum(len(changes[k]) for k in ("modified", "missing", "new_persistence")
                  if any(severity(k, p) == "warning" for p in changes[k])) if not burst else \
        sum(len(changes[k]) for k in ("modified", "missing", "new_persistence"))
    if burst:
        print(f"[WARN] {len(docs_changed)} documents changed or went missing in one check. Editing doesn't look like this.")
        record_event("integrity", "warning", "file_changes",
                     f"{len(docs_changed)} of your documents changed or went missing at once, which isn't ordinary editing (the shape of ransomware)")
    elif flagged > MAX_EVENTS:
        record_event("integrity", "warning", "file_changes", f"{flagged} watched files changed or went missing (first {MAX_EVENTS} listed above)")

    # Honeypot: report an access once, then remember it.
    hp_now = honeypot_state()
    hp_then = meta.get("honeypot")
    if hp_now and hp_then and hp_now["atime"] > hp_then["atime"] and _ours(hp_now["atime"]):
        # The virus scan runs just before this check, and a scan that goes through the ClamAV daemon can't be told to skip the decoy.
        # A read inside our own scan window is ours: remember the new access time and say nothing.
        meta["honeypot"] = hp_now
        meta_file().write_text(json.dumps(meta))
        print("[INFO] The honeypot's access time moved during a LinuxGuardian scan: not treated as an intruder.")
    elif hp_now and hp_then and hp_now["atime"] > hp_then["atime"]:
        any_change = True
        print(f"[WARN] Honeypot file was read: possible unauthorized access to {honeypot_dir()}")
        record_event("honeypot", "critical", "honeypot_read", f"Honeypot accessed at {honeypot_dir()}")
        meta["honeypot"] = hp_now
        meta_file().write_text(json.dumps(meta))
    elif hp_now and hp_then and (hp_now["mtime"] != hp_then["mtime"] or hp_now["size"] != hp_then["size"]):
        any_change = True
        print("[WARN] The honeypot file was modified.")
        record_event("honeypot", "critical", "honeypot_modified", f"Honeypot modified at {honeypot_dir()}")
        meta["honeypot"] = hp_now
        meta_file().write_text(json.dumps(meta))

    if not any_change:
        print("[ OK ] No changes detected. Integrity intact.")
    progress("Integrity check complete", pct=100, total=len(old))
    return 0


def _ours(epoch: float) -> bool:
    """Was this moment during (or just after) one of our own scans, or is one running?"""
    try:
        import decoys

        return decoys.scan_running() or any(a <= epoch <= b for a, b in decoys.scan_windows())
    except Exception:  # noqa: BLE001 - the integrity check must work without the decoy module
        return False


def _watched(path: Path) -> bool:
    return any(path == r or r in path.parents for r in roots()) and not excluded(str(path))


def accept_paths(paths: list[str], forget: bool = False) -> tuple[int, list[str]]:
    """Tell the baseline about a change LinuxGuardian itself just made (installing or removing its own timers), so the daily check
    doesn't report our own work as something new or missing. Only files inside the watched places; only ones that exist (or, for
    `forget`, entries already in the baseline). Returns (changed, refused)."""
    base = read_baseline()
    if base is None:
        return 0, list(paths)
    changed, refused = 0, []
    for raw in paths:
        p = Path(raw)
        key = str(p)
        if not p.is_absolute() or not _watched(p):
            refused.append(raw)
            continue
        if forget:
            if key in base:
                del base[key]
                changed += 1
            continue
        if p.is_symlink() or not p.is_file():
            refused.append(raw)
            continue
        digest = sha256(p)
        if digest is None:
            refused.append(raw)
            continue
        if base.get(key) != digest:
            base[key] = digest
            changed += 1
    if changed:
        meta = read_meta()
        tmp = baseline_file().with_suffix(".tmp")
        tmp.write_text("".join(f"{h}  {pth}\n" for pth, h in sorted(base.items())))
        tmp.replace(baseline_file())
        meta["files"] = len(base)
        meta_file().write_text(json.dumps(meta))
    return changed, refused


def status_dict(now: float | None = None) -> dict:
    now = time.time() if now is None else now
    meta = read_meta()
    baseline = read_baseline()
    if baseline is None:
        return {"present": False}
    created = meta.get("created_epoch")
    if created is None:
        p = baseline_file() if baseline_file().is_file() else legacy_baseline()
        created = int(p.stat().st_mtime)
    return {"present": True, "created_epoch": created, "age_sec": max(0, int(now - created)),
            "files": len(baseline), "roots": meta.get("roots"),
            "covers_extra_locations": meta.get("roots") is not None}


def do_status() -> int:
    print(json.dumps(status_dict()))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group(required=True)
    for flag in ("init", "check", "status", "roots"):
        g.add_argument(f"--{flag}", action="store_true")
    g.add_argument("--accept", nargs="+", metavar="PATH", help="record files LinuxGuardian itself just created or changed as normal")
    g.add_argument("--forget", nargs="+", metavar="PATH", help="drop files LinuxGuardian itself just removed from the baseline")
    a = p.parse_args()
    if a.accept or a.forget:
        n, refused = accept_paths(a.accept or a.forget, forget=bool(a.forget))
        print(f"Baseline updated for {n} file(s)." + (f" Not touched: {', '.join(refused)}" if refused else ""))
        return 0
    if a.init:
        return do_init()
    if a.check:
        return do_check()
    if a.status:
        return do_status()
    for r in roots():
        print(r)
    return 0


if __name__ == "__main__":
    sys.exit(main())

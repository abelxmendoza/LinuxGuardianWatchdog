#!/usr/bin/env python3
"""Is LinuxGuardian itself healthy, and has anyone tampered with it?  (read-only unless you ask for a repair)

A security tool is a target. This checks the app's own foundations:

  * app files      the program files still match the baseline recorded when they were last trusted (hashes), and the
                   change is judged against git when the install is a checkout: a clean update is not an alert, an
                   edit that isn't a clean update is
  * permissions    nobody else can write to the app, and other users on this laptop can't read your data folder
  * saved state    each settings/state file still parses; a damaged one can be restored from a daily backup
  * allow-list     nothing suspicious has been added to the "this is expected" list (it is how an intruder would hide)
  * monitoring     the live-monitoring timer is on and has actually run recently
  * space          the data folder isn't running the disk out

Honest limit: an attacker who already controls your account can edit the app AND its baseline. This reliably catches
accidents, half-finished updates and unsophisticated tampering, and the sensors raise an alert; it can't promise more.

  self_check.py --check [--json]          run every check
  self_check.py --plan REPAIR             show exactly what a repair would change (changes nothing)
  self_check.py --apply REPAIR            do it.   REPAIR: perms | app_perms | accept | state:NAME
  self_check.py --maintain                daily upkeep: snapshot state files, rotate the log, prune old snapshots
  self_check.py --heartbeat               dead-man's switch: warn if live monitoring was switched off or stopped (the daily scan runs this)

Test hooks: LG_HOME, LG_APP_ROOT, LG_SELF_NOW.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

from events import lg_home  # noqa: E402

LEVELS = {"ok": 0, "info": 1, "warning": 2, "critical": 3}
APP_GLOBS = ("LinuxGuardianSuite/*", "LinuxGuardianSuiteUI/linuxguardian_ui/**/*", "LinuxGuardianSuiteUI/resources/*.css", "LinuxGuardianSuiteUI/run_ui.sh")
TRUSTED_TMP = ("/tmp/", "/var/tmp/", "/dev/shm/")
SENSORS_STALE = 30 * 60              # a 5-minute timer that hasn't run for half an hour has stopped
MAX_LIST = 20
MIN_FREE_MB = 500
BIG_LOG = 200 * 1024 * 1024
LOG_ROTATE_AT = 5 * 1024 * 1024
BACKUP_KEEP_DAYS = 7

# name -> path relative to the data folder (these are the files whose damage would hurt, and that we can restore)
STATE_FILES = {
    "sensors": "state/sensors.json",
    "ai": "ai.json",
    "allow": "sensors_allow.json",
    "ack": "state/timeline_ack.json",
    "hardening_undo": "state/hardening_undo.json",
    "scan_last": "scans/last.json",
    "self_manifest": "state/self_manifest.json",
}


def now() -> float:
    return float(os.environ.get("LG_SELF_NOW") or time.time())


def app_root() -> Path:
    return Path(os.environ.get("LG_APP_ROOT") or SUITE_DIR.parent)


def manifest_path() -> Path:
    return lg_home() / STATE_FILES["self_manifest"]


def backup_root() -> Path:
    return lg_home() / "backups"


# =========================================================== app files
def app_files(root: Path | None = None) -> dict[str, dict]:
    """Every file the app runs, relative path -> hash and permissions."""
    root = root or app_root()
    out: dict[str, dict] = {}
    for pattern in APP_GLOBS:
        for p in root.glob(pattern):
            if "__pycache__" in p.parts or p.suffix == ".pyc" or p.is_symlink() or not p.is_file():
                continue
            try:
                st = p.stat()
                digest = hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError:
                continue
            out[str(p.relative_to(root))] = {"sha": digest, "mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid, "gid": st.st_gid}
    return out


def git_info(root: Path | None = None) -> dict:
    """Head commit, and which app files differ from it (including untracked ones)."""
    root = root or app_root()
    if not (root / ".git").exists() or not shutil.which("git"):
        return {"present": False, "head": "", "dirty": [], "tracked": set()}
    env = dict(os.environ, LC_ALL="C", GIT_OPTIONAL_LOCKS="0")

    def git(*args: str) -> str:
        try:
            return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=20, env=env, check=False).stdout
        except (OSError, subprocess.TimeoutExpired):
            return ""

    head = git("rev-parse", "HEAD").strip()
    if not head:
        return {"present": False, "head": "", "dirty": [], "tracked": set()}
    dirty = []
    for line in git("status", "--porcelain", "--untracked-files=all", "--", "LinuxGuardianSuite", "LinuxGuardianSuiteUI/linuxguardian_ui",
                    "LinuxGuardianSuiteUI/resources", "LinuxGuardianSuiteUI/run_ui.sh").splitlines():
        path = line[3:].strip().strip('"')
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        if path:
            dirty.append(path)
    tracked = set(git("ls-files").splitlines())
    return {"present": True, "head": head, "dirty": dirty, "tracked": tracked}


def load_manifest() -> dict | None:
    try:
        d = json.loads(manifest_path().read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return d if isinstance(d, dict) and isinstance(d.get("files"), dict) else None


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    tmp.replace(path)


def record_baseline(root: Path | None = None) -> dict:
    files = app_files(root)
    g = git_info(root)
    m = {"created": now(), "head": g["head"], "files": {k: {"sha": v["sha"], "mode": v["mode"]} for k, v in files.items()}}
    _write_private(manifest_path(), json.dumps(m))
    return m


def compare(manifest: dict, files: dict[str, dict]) -> dict:
    old = manifest["files"]
    return {"changed": sorted(k for k in files if k in old and old[k].get("sha") != files[k]["sha"]),
            "added": sorted(k for k in files if k not in old), "removed": sorted(k for k in old if k not in files)}


def _short(rel: list[str]) -> str:
    shown = ", ".join(rel[:3])
    return shown + (f" and {len(rel) - 3} more" if len(rel) > 3 else "")


def judge_app_files(root: Path | None = None, create: bool = True) -> dict:
    """The verdict on the app's own files: level, text, detail, the changed paths, and whether 'accept' is offered."""
    root = root or app_root()
    files = app_files(root)
    manifest = load_manifest()
    if manifest is None and manifest_path().exists():
        # Never quietly re-baseline over a damaged baseline: that is exactly what tampering would look like.
        return {"id": "app_files", "title": "App files", "level": "warning", "detail": [], "paths": [], "repair": "state:self_manifest",
                "text": "The saved baseline of the app's files is damaged, so the files can't be checked. Restore it from a backup."}
    if manifest is None:
        if not create:
            return {"id": "app_files", "title": "App files", "level": "info", "text": "No baseline yet.", "detail": [], "paths": [], "repair": "accept"}
        m = record_baseline(root)
        return {"id": "app_files", "title": "App files", "level": "info", "detail": [], "paths": [], "repair": None,
                "text": f"First run: recorded a baseline of {len(m['files'])} app files to compare against from now on."}
    diff = compare(manifest, files)
    n = len(diff["changed"]) + len(diff["added"]) + len(diff["removed"])
    g = git_info(root)
    if n == 0:
        return {"id": "app_files", "title": "App files", "level": "ok", "detail": [], "paths": [], "repair": None,
                "text": f"All {len(files)} app files match the trusted baseline" + (f" (version {g['head'][:8]})." if g["head"] else ".")}
    paths = diff["changed"] + diff["added"] + diff["removed"]
    detail = [f"changed: {p}" for p in diff["changed"]] + [f"new: {p}" for p in diff["added"]] + [f"missing: {p}" for p in diff["removed"]]
    # Serious regardless of git: a file anyone can write to, or one owned by another user. A brand-new program file is also serious when
    # there is no git history to explain it. In a git checkout, an uncommitted new file is what DEVELOPING looks like (and is visible to
    # `git status`), so there it is a warning in the health window and a quiet note in the Timeline, never an alarm.
    unknown_new = [p for p in diff["added"] if not g["present"]]
    uncommitted = [p for p in diff["added"] if g["present"] and p not in g["tracked"]]
    writable = [p for p in paths if p in files and files[p]["mode"] & stat.S_IWOTH]
    foreign = [p for p in paths if p in files and files[p]["uid"] not in (os.getuid(), 0)]
    base = {"id": "app_files", "title": "App files", "detail": detail[:MAX_LIST], "paths": paths, "repair": "accept", "dev_checkout": g["present"]}
    if unknown_new or writable or foreign:
        why = []
        if unknown_new:
            why.append(f"{len(unknown_new)} new program file(s) that aren't part of the published version")
        if writable:
            why.append("files anyone on this laptop can modify")
        if foreign:
            why.append("files owned by another user")
        return {**base, "level": "critical", "sensor_level": "critical",
                "text": f"{n} app file(s) differ from the baseline, including " + " and ".join(why) + ": " + _short(paths) + ". "
                "If you didn't do this, treat it as tampering."}
    if g["present"] and not g["dirty"] and manifest.get("head") and g["head"] != manifest["head"]:
        return {**base, "level": "info", "sensor_level": "info",
                "text": f"The app was updated ({manifest['head'][:8]} to {g['head'][:8]}): {n} file(s) differ from your saved baseline, "
                "and they match the published version. Accept it to re-record the baseline."}
    if g["present"]:
        what = f"{len(diff['changed'])} changed and {len(uncommitted)} new" if uncommitted else f"{n} changed"
        return {**base, "level": "warning", "sensor_level": "info",
                "text": f"{what} app file(s) with uncommitted changes in this git checkout: {_short(paths)}. That is normal while you are editing LinuxGuardian; "
                "if you aren't, look at `git status` in the app folder."}
    return {**base, "level": "warning", "sensor_level": "warning",
            "text": f"{n} app file(s) were modified since the baseline and it isn't a clean update: {_short(paths)}. "
            "If you edited them yourself, accept the change. If not, treat it as tampering."}


# ====================================================== permissions
def _mode(path: Path) -> int | None:
    try:
        return stat.S_IMODE(path.lstat().st_mode)
    except OSError:
        return None


def data_perm_plan() -> list[dict]:
    """What would be tightened in the data folder: path, current mode, wanted mode. Symlinks are never followed.

    A private top folder (700) already keeps everything beneath it away from other users, so nothing else is flagged then.
    """
    home = lg_home()
    if home.is_symlink() or not home.is_dir():
        return []
    m = _mode(home)
    if m is not None and m & 0o077:
        return [{"path": str(home), "from": m, "to": 0o700}]
    return []


def app_perm_plan(root: Path | None = None) -> list[dict]:
    """App files/folders others can write to (owned by you, so you can fix them)."""
    root = root or app_root()
    plan = []
    for rel, info in app_files(root).items():
        if info["mode"] & stat.S_IWOTH and info["uid"] == os.getuid():
            plan.append({"path": str(root / rel), "from": info["mode"], "to": info["mode"] & ~stat.S_IWOTH})
    for d in (root, root / "LinuxGuardianSuite", root / "LinuxGuardianSuiteUI" / "linuxguardian_ui"):
        try:
            st = d.lstat()
        except OSError:
            continue
        if stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_IWOTH and st.st_uid == os.getuid():
            plan.append({"path": str(d), "from": stat.S_IMODE(st.st_mode), "to": stat.S_IMODE(st.st_mode) & ~stat.S_IWOTH})
    return plan


def check_app_permissions(root: Path | None = None) -> dict:
    root = root or app_root()
    files = app_files(root)
    world = [p for p, i in files.items() if i["mode"] & stat.S_IWOTH]
    foreign = [p for p, i in files.items() if i["uid"] not in (os.getuid(), 0)]
    dirs = [str(d) for d in (root, root / "LinuxGuardianSuite") if d.is_dir() and _mode(d) is not None and _mode(d) & stat.S_IWOTH]
    mygroup = os.getgid()
    shared_group = [p for p, i in files.items() if i["mode"] & stat.S_IWGRP and i["gid"] != mygroup and i["gid"] != 0]
    base = {"id": "app_permissions", "title": "Who can change the app"}
    if world or dirs or foreign:
        bits = []
        if world:
            bits.append(f"{len(world)} file(s) anyone on this laptop can modify")
        if dirs:
            bits.append("the app folder itself is open to everyone")
        if foreign:
            bits.append(f"{len(foreign)} file(s) owned by another user")
        return {**base, "level": "critical", "text": "; ".join(bits).capitalize() + ": that lets another account change what LinuxGuardian runs.",
                "detail": [f"{p}" for p in (world + foreign)[:MAX_LIST]], "repair": "app_perms" if (world or dirs) else None}
    if shared_group:
        return {**base, "level": "warning", "text": f"{len(shared_group)} app file(s) can be changed by members of a shared group.",
                "detail": shared_group[:MAX_LIST], "repair": None}
    return {**base, "level": "ok", "text": "Only you (and the administrator) can change the app's files.", "detail": [], "repair": None}


def check_data_permissions() -> dict:
    plan = data_perm_plan()
    base = {"id": "data_permissions", "title": "Who can read your LinuxGuardian data"}
    if not lg_home().is_dir():
        return {**base, "level": "ok", "text": "No data folder yet.", "detail": [], "repair": None}
    if plan:
        return {**base, "level": "warning", "repair": "perms", "text": "Your ~/.linuxguardian folder can be opened by other users on this laptop "
                "(it holds evidence, logs and settings). Making the folder private (700) protects everything inside it.", "detail": [f"{p['path']}: {p['from']:o} should be {p['to']:o}" for p in plan[:MAX_LIST]]}
    return {**base, "level": "ok", "text": "Your data folder is private to you.", "detail": [], "repair": None}


# ============================================================ state
def _parses(path: Path) -> bool:
    try:
        json.loads(path.read_text())
        return True
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return False


def state_path(name: str) -> Path:
    if name not in STATE_FILES:
        raise ValueError("unknown state file")
    return lg_home() / STATE_FILES[name]


def newest_backup(name: str) -> tuple[Path, str] | None:
    """Newest backup copy of a state file that still parses: (path, its date)."""
    root = backup_root()
    if not root.is_dir():
        return None
    rel = STATE_FILES[name]
    for d in sorted((x for x in root.iterdir() if x.is_dir() and re.fullmatch(r"\d{8}", x.name)), reverse=True):
        cand = d / rel.replace("/", "__")
        if cand.is_file() and _parses(cand):
            return cand, d.name
    return None


def check_state() -> dict:
    bad = []
    for name in STATE_FILES:
        p = state_path(name)
        if p.exists() and not _parses(p):
            bad.append(name)
    base = {"id": "state", "title": "Saved settings and state"}
    if not bad:
        return {**base, "level": "ok", "text": "All saved settings and state files are readable.", "detail": [], "repair": None}
    detail = []
    for n in bad:
        b = newest_backup(n)
        detail.append(f"{STATE_FILES[n]}: damaged; " + (f"a good backup from {b[1]} exists" if b else "no backup, it can be reset"))
    return {**base, "level": "warning", "text": f"{len(bad)} state file(s) are damaged: {', '.join(STATE_FILES[n] for n in bad)}.", "detail": detail,
            "repair": "state:" + bad[0], "repairs": ["state:" + n for n in bad]}


def check_allow_list() -> dict:
    base = {"id": "allow_list", "title": "The 'this is expected' list", "repair": None}
    p = lg_home() / STATE_FILES["allow"]
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return {**base, "level": "ok", "text": "Nothing has been allow-listed.", "detail": []}
    exes = [str(e) for e in (data.get("exe") or []) if isinstance(e, str)] if isinstance(data, dict) else []
    home = str(Path.home())
    odd = [e for e in exes if e.startswith(TRUSTED_TMP) or re.search(r"/\.[^/]+/", e.replace(home, "", 1) if e.startswith(home) else "")]
    if odd:
        return {**base, "level": "warning", "text": f"{len(odd)} of {len(exes)} allow-listed program(s) are in temporary or hidden folders, which is where "
                "an intruder would hide.", "detail": odd[:MAX_LIST]}
    return {**base, "level": "ok", "text": f"{len(exes)} program(s) allow-listed, none in temporary or hidden folders." if exes else "Nothing has been allow-listed.", "detail": []}


# ========================================================= monitoring
def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def check_monitoring() -> dict:
    base = {"id": "monitoring", "title": "Live monitoring", "repair": None}
    try:
        state = json.loads(state_path("sensors").read_text())
    except (OSError, json.JSONDecodeError):
        state = {}
    last = state.get("last_run")
    timer = _run(["systemctl", "--user", "is-enabled", "linuxguardian-sensors.timer"]) == "enabled" if shutil.which("systemctl") else None
    if timer is None:
        return {**base, "level": "info", "text": "systemd isn't available, so live monitoring can't be scheduled.", "detail": []}
    if not timer:
        return {**base, "level": "info", "text": "Live monitoring is off (turn it on in the Incidents tab).", "detail": []}
    if last is None:
        return {**base, "level": "warning", "text": "Live monitoring is on but has never run.", "detail": ["Run it once: " + str(SUITE_DIR / "sensors.py") + " --run"]}
    age = now() - last
    if age > SENSORS_STALE:
        return {**base, "level": "warning", "text": f"Live monitoring is on but hasn't run for {int(age // 60)} minutes. It may have stopped or been disabled.",
                "detail": ["systemctl --user status linuxguardian-sensors.timer"]}
    return {**base, "level": "ok", "text": f"Live monitoring is on and ran {int(age // 60)} minute(s) ago.", "detail": []}


def dir_size(path: Path, cap: int = 2_000_000_000) -> int:
    total = 0
    for root, _dirs, names in os.walk(path):
        for n in names:
            try:
                total += os.lstat(os.path.join(root, n)).st_size
            except OSError:
                pass
            if total > cap:
                return total
    return total


def check_space() -> dict:
    base = {"id": "space", "title": "Disk space used by LinuxGuardian", "repair": None}
    home = lg_home()
    if not home.is_dir():
        return {**base, "level": "ok", "text": "Nothing stored yet.", "detail": []}
    size = dir_size(home)
    try:
        free = shutil.disk_usage(home).free
    except OSError:
        free = None
    mb = size / 1024 / 1024
    if free is not None and free < MIN_FREE_MB * 1024 * 1024:
        return {**base, "level": "warning", "text": f"Only {free // 1024 // 1024} MB of disk is free. Scans and logs can fail.", "detail": []}
    if size > BIG_LOG:
        return {**base, "level": "warning", "text": f"The data folder has grown to {mb:,.0f} MB.", "detail": ["du -sh ~/.linuxguardian/* | sort -h"]}
    return {**base, "level": "ok", "text": f"{mb:,.1f} MB used.", "detail": []}


# ============================================================= engine
def check(create_baseline: bool = True) -> dict:
    checks = [judge_app_files(create=create_baseline), check_app_permissions(), check_data_permissions(), check_state(), check_allow_list(),
              check_monitoring(), check_space()]
    worst = max(checks, key=lambda c: LEVELS[c["level"]])["level"]
    problems = [c for c in checks if LEVELS[c["level"]] >= LEVELS["warning"]]
    n = len(problems)
    headline = ("LinuxGuardian is healthy." if worst in ("ok", "info") else
                (f"{n} thing needs attention" if n == 1 else f"{n} things need attention") + (" and it is serious." if worst == "critical" and n == 1 else
                                                                                                " (one is serious)." if worst == "critical" else "."))
    return {"time": now(), "level": worst, "headline": headline, "checks": checks}


def sensor_findings() -> list[dict]:
    """For the live sensors: the app-file verdict, as plain dicts, with the severity the SENSOR should use (`sensor_level`).

    The health window may call uncommitted edits in a git checkout a warning; the sensor treats them as routine information, so editing
    LinuxGuardian never raises an alarm or a desktop notification. Tampering signs (writable or foreign-owned files, new program files
    with no git history to explain them) stay critical.
    """
    c = judge_app_files(create=True)
    if c.get("paths") and c.get("sensor_level") in ("critical", "warning", "info") and c["level"] != "ok":
        return [c]
    return []


# ============================================================ repairs
REPAIR_RE = re.compile(r"perms|app_perms|accept|state:[a-z_]{1,20}")


def plan(repair: str) -> dict:
    """What a repair would do. Never changes anything."""
    if not REPAIR_RE.fullmatch(repair or ""):
        raise ValueError("unknown repair")
    if repair == "perms":
        steps = [f"{p['path']}: {p['from']:o} -> {p['to']:o}" for p in data_perm_plan()]
        return {"repair": repair, "title": "Make your data folder private", "steps": steps or ["Nothing to change."],
                "note": "Only permission bits change; no file contents are touched."}
    if repair == "app_perms":
        steps = [f"{p['path']}: {p['from']:o} -> {p['to']:o}" for p in app_perm_plan()]
        return {"repair": repair, "title": "Stop others from writing to the app", "steps": steps or ["Nothing to change."],
                "note": "Removes write access for other users on files you own."}
    if repair == "accept":
        j = judge_app_files(create=False)
        return {"repair": repair, "title": "Accept the app's current files as trusted", "steps": j["detail"] or ["Record the current files as the baseline."],
                "note": "Only do this if you updated or edited the app yourself. If you didn't, investigate first."}
    name = repair.split(":", 1)[1]
    if name not in STATE_FILES:
        raise ValueError("unknown repair")
    b = newest_backup(name)
    step = (f"Restore {STATE_FILES[name]} from the backup of {b[1]} (the damaged file is kept beside it as .corrupt)." if b else
            f"Move the damaged {STATE_FILES[name]} aside (kept as .corrupt) so a fresh one is created.")
    return {"repair": repair, "title": "Repair a damaged state file", "steps": [step], "note": "The damaged copy is kept, not deleted."}


def _chmod_all(items: list[dict]) -> int:
    n = 0
    for it in items:
        p = Path(it["path"])
        if p.is_symlink() or not p.exists():
            continue
        try:
            os.chmod(p, it["to"])
            n += 1
        except OSError:
            pass
    return n


def apply(repair: str) -> str:
    plan(repair)                                           # validates the name
    if repair == "perms":
        return f"Tightened {_chmod_all(data_perm_plan())} item(s)."
    if repair == "app_perms":
        return f"Tightened {_chmod_all(app_perm_plan())} item(s)."
    if repair == "accept":
        m = record_baseline()
        return f"Recorded {len(m['files'])} app files as the trusted baseline."
    name = repair.split(":", 1)[1]
    p = state_path(name)
    if p.exists() and not _parses(p):
        kept = p.with_name(p.name + f".corrupt-{int(now())}")
        p.replace(kept)
    b = newest_backup(name)
    if b:
        shutil.copy2(b[0], p)
        os.chmod(p, 0o600)
        return f"Restored {STATE_FILES[name]} from the backup of {b[1]}."
    return f"Moved the damaged {STATE_FILES[name]} aside; a fresh one will be created."


# =========================================================== upkeep
def maintain() -> dict:
    """Daily upkeep. Safe to run any time: snapshot good state files, rotate the main log, drop old snapshots."""
    home = lg_home()
    done = {"backed_up": 0, "rotated": False, "pruned": 0}
    stamp = time.strftime("%Y%m%d", time.localtime(now()))
    dest = backup_root() / stamp
    for name, rel in STATE_FILES.items():
        src = home / rel
        if not src.is_file() or not _parses(src):
            continue                                       # never snapshot a damaged file over a good one
        dest.mkdir(parents=True, exist_ok=True)
        os.chmod(dest, 0o700)
        os.chmod(backup_root(), 0o700)
        target = dest / rel.replace("/", "__")
        shutil.copy2(src, target)
        os.chmod(target, 0o600)
        done["backed_up"] += 1
    log = home / "logs" / "linuxguardian.log"
    try:
        if log.is_file() and log.stat().st_size > LOG_ROTATE_AT:
            for i in (2, 1):                                   # keep three generations: .1 newest, .3 oldest
                older = log.with_name(f"{log.name}.{i}")
                if older.exists():
                    older.replace(log.with_name(f"{log.name}.{i + 1}"))
            log.replace(log.with_name(log.name + ".1"))
            done["rotated"] = True
    except OSError:
        pass
    root = backup_root()
    if root.is_dir():
        cutoff = now() - BACKUP_KEEP_DAYS * 86400
        for d in root.iterdir():
            if d.is_dir() and re.fullmatch(r"\d{8}", d.name):
                try:
                    when = time.mktime(time.strptime(d.name, "%Y%m%d"))
                except ValueError:
                    continue
                if when < cutoff:
                    shutil.rmtree(d, ignore_errors=True)
                    done["pruned"] += 1
    return done


# ================================================== dead-man's switch
HEARTBEAT_STALE = 6 * 3600           # the daily scan raises this if the 5-minute monitor hasn't run for six hours
HEARTBEAT_COOLDOWN = 24 * 3600


def heartbeat() -> dict | None:
    """Run by a DIFFERENT unit (the daily scan), so it still speaks if the live monitor was switched off or killed.

    Only speaks if live monitoring has really been in use (its timer was seen enabled), never to nag someone who didn't turn it on.
    Records a warning event (at most once a day) and returns it, or returns None.
    """
    try:
        state = json.loads(state_path("sensors").read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(state, dict) or not state.get("timer_seen"):
        return None
    timer = _run(["systemctl", "--user", "is-enabled", "linuxguardian-sensors.timer"]) == "enabled" if shutil.which("systemctl") else None
    last = state.get("last_run")
    age = None if last is None else now() - last
    if timer is False:
        problem = "Live monitoring was switched off: its timer is no longer enabled, so nothing is watching for attacks between scans."
    elif age is not None and age > HEARTBEAT_STALE:
        problem = f"Live monitoring hasn't run for {int(age // 3600)} hours, so nothing is watching for attacks. It may have been stopped."
    else:
        return None
    hb = lg_home() / "state" / "self_heartbeat.json"
    try:
        last_alert = json.loads(hb.read_text()).get("time", 0)
    except (OSError, json.JSONDecodeError):
        last_alert = 0
    if now() - last_alert < HEARTBEAT_COOLDOWN:
        return None
    from events import record_event

    record_event("selfcheck", "warning", "monitoring_stopped", problem + " Turn it back on from the Incidents tab, or: systemctl --user enable --now linuxguardian-sensors.timer",
                 technique="T1562.001")
    _write_private(hb, json.dumps({"time": now()}))
    return {"event": "monitoring_stopped", "message": problem}


# ================================================================= CLI
def render_text(r: dict) -> str:
    mark = {"ok": "ok  ", "info": "info", "warning": "WARN", "critical": "CRIT"}
    lines = [r["headline"], ""]
    for c in r["checks"]:
        lines.append(f"[{mark[c['level']]}] {c['title']}: {c['text']}")
        lines += [f"       {d}" for d in c["detail"][:5]]
        if c.get("repair"):
            lines.append(f"       fix: {Path(__file__).resolve()} --plan {c['repair']}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--plan", metavar="REPAIR")
    g.add_argument("--apply", metavar="REPAIR")
    g.add_argument("--maintain", action="store_true")
    g.add_argument("--heartbeat", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    try:
        if a.check:
            r = check()
            print(json.dumps(r) if a.json else render_text(r))
        elif a.plan:
            p = plan(a.plan)
            print(json.dumps(p) if a.json else "\n".join([p["title"], *[f"  - {s}" for s in p["steps"]], p["note"]]))
        elif a.apply:
            print(apply(a.apply))
        elif a.heartbeat:
            r = heartbeat()
            print(json.dumps(r) if a.json else (r["message"] if r else "Live monitoring is fine (or was never turned on)."))
        else:
            r = maintain()
            print(json.dumps(r) if a.json else f"Backed up {r['backed_up']} file(s); log rotated: {r['rotated']}; old snapshots removed: {r['pruned']}.")
    except ValueError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

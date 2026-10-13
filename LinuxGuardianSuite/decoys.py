#!/usr/bin/env python3
"""Decoy files: fake secrets that nothing legitimate ever opens, so anything that does is worth a look.

An intruder (or a malicious script) that has landed on a laptop goes hunting for SSH keys, cloud credentials and .env files.
Three clearly fake ones are planted where those hunters look. They are NOT real credentials: random look-alike text that
unlocks nothing. If one is later read, changed or deleted, that is reported as critical.

How "was it read" works: Linux records when a file was last read (its access time). A decoy is created with an access time
older than its modification time, so the very next read bumps it; after each check it is re-armed. Honest limits:
  * this only works if the filesystem updates access times; `--status` tests that on your disk and says so if it doesn't
  * it can't tell you WHICH program read it; backup tools, file indexers and virus scans can also read it. LinuxGuardian's
    own scans and file-integrity checks skip the decoys, and reads that happen while one of them is running are ignored
  * it is a tripwire, not a lock: it adds nothing to protect your real files

  decoys.py --create     plant the decoys (never overwrites a file that is already there)
  decoys.py --status     where they are and whether read-detection works on this disk
  decoys.py --check      look for reads/changes now (the live monitor does this every 5 minutes)
  decoys.py --remove     take them away again

Test hooks: LG_HOME, LG_SENSOR_HOME (stand-in for $HOME), LG_PROC, LG_DECOY_NOW.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import string
import sys
import time
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

from events import lg_home  # noqa: E402

ARM_GAP = 10                        # the armed access time sits this many seconds before the modification time
SCAN_GRACE = 90                     # reads this close to one of our own scans are ours
SCAN_PROGRAMS = ("linux_guardian.sh", "clamscan", "clamdscan", "rkhunter")     # what could read a decoy; the integrity check skips them and is not in this list

SPECS = [
    {"id": "ssh", "rel": ".ssh/old_deploy_key", "what": "a private SSH key", "dir_mode": 0o700},
    {"id": "aws", "rel": ".aws/credentials.bak", "what": "cloud (AWS) credentials", "dir_mode": 0o700},
    {"id": "env", "rel": ".env.production.bak", "what": "an environment file with passwords", "dir_mode": None},
]


def now() -> float:
    return float(os.environ.get("LG_DECOY_NOW") or time.time())


def home() -> Path:
    return Path(os.environ.get("LG_SENSOR_HOME", str(Path.home())))


def state_path() -> Path:
    return lg_home() / "state" / "decoys.json"


def paths(base: Path | None = None) -> list[Path]:
    """Where decoys live (whether or not they exist yet). Used by scans and integrity checks to leave them alone."""
    base = base or home()
    return [base / s["rel"] for s in SPECS]


def _rand(n: int, alphabet: str) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def content(spec_id: str) -> str:
    b64 = string.ascii_letters + string.digits + "+/"
    if spec_id == "ssh":
        lines = [_rand(70, b64) for _ in range(24)]
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END OPENSSH PRIVATE KEY-----\n"
    if spec_id == "aws":
        return ("[default]\naws_access_key_id = AKIA" + _rand(16, string.ascii_uppercase + string.digits)
                + "\naws_secret_access_key = " + _rand(40, b64) + "\nregion = us-east-1\n")
    return ("# production secrets (old copy)\nDATABASE_URL=postgres://admin:" + _rand(18, string.ascii_letters + string.digits) + "@10.0.0.9:5432/prod\n"
            "SECRET_KEY=" + _rand(48, string.ascii_letters + string.digits) + "\nSTRIPE_API_KEY=sk_live_" + _rand(24, string.ascii_letters + string.digits) + "\n")


def load_state() -> dict:
    try:
        d = json.loads(state_path().read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict) -> None:
    p = state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(state))
    tmp.replace(p)


def atime_works(directory: Path) -> bool:
    """Does reading a file in this folder update its access time? (A 'noatime' mount makes read-detection impossible.)"""
    probe = directory / f".lg-atime-probe-{secrets.token_hex(3)}"
    try:
        fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        t = time.time()
        os.utime(probe, (t - 100, t - 50))                    # access older than modification: the 'relatime' rule says the next read updates it
        probe.read_bytes()
        return os.stat(probe).st_atime > t - 100 + 1
    except OSError:
        return False
    finally:
        try:
            probe.unlink()
        except OSError:
            pass


def arm(path: Path) -> int:
    """Set the access time just before the modification time so the next read is visible. Returns the armed atime (ns)."""
    st = os.stat(path)
    os.utime(path, ns=(st.st_mtime_ns - ARM_GAP * 10 ** 9, st.st_mtime_ns))
    return os.stat(path).st_atime_ns


def create() -> dict:
    """Plant the decoys that aren't there. Never overwrites or follows anything that exists."""
    state = load_state()
    made, skipped = [], []
    base = home()
    for spec in SPECS:
        p = base / spec["rel"]
        if str(p) in state.get("items", {}) and p.exists():
            continue
        if os.path.lexists(p):
            skipped.append({"path": str(p), "why": "A file with that name already exists, so it was left alone."})
            continue
        if not p.parent.exists():
            p.parent.mkdir(mode=spec["dir_mode"] or 0o755, parents=True)
        elif p.parent.is_symlink():
            skipped.append({"path": str(p), "why": "The folder is a symbolic link."})
            continue
        try:
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:                                # appeared between the check above and now
            skipped.append({"path": str(p), "why": "A file with that name already exists, so it was left alone."})
            continue
        with os.fdopen(fd, "w") as f:
            f.write(content(spec["id"]))
        st = os.stat(p)
        armed = arm(p)
        state.setdefault("items", {})[str(p)] = {"id": spec["id"], "ino": st.st_ino, "size": st.st_size, "mtime_ns": st.st_mtime_ns,
                                                  "armed_atime_ns": armed, "created": now(),
                                                  "planted": {"ino": st.st_ino, "size": st.st_size, "mtime_ns": st.st_mtime_ns}}
        made.append(str(p))
    state["atime_works"] = atime_works(base)
    save_state(state)
    return {"created": made, "skipped": skipped, "read_detection": state["atime_works"]}


def remove() -> dict:
    """Remove only decoys that are still exactly what was planted. A file that was replaced or edited since (inode numbers get
    reused, so the size and timestamp are checked too) is left alone."""
    state = load_state()
    removed, kept = [], []
    for p, meta in list(state.get("items", {}).items()):
        path = Path(p)
        try:
            st = os.lstat(path)
        except OSError:
            continue
        planted = meta.get("planted") or {}
        if (stat.S_ISREG(st.st_mode) and st.st_ino == planted.get("ino") and st.st_size == planted.get("size")
                and st.st_mtime_ns == planted.get("mtime_ns")):
            path.unlink()
            removed.append(p)
        else:
            kept.append(p)
    state["items"] = {}
    save_state(state)
    return {"removed": removed, "kept": kept}


def scan_windows() -> list[tuple[float, float]]:
    try:
        d = json.loads((lg_home() / "scans" / "last.json").read_text())
    except (OSError, json.JSONDecodeError):
        return []
    s, e = d.get("started_epoch"), d.get("ended_epoch")
    return [(float(s) - SCAN_GRACE, float(e) + SCAN_GRACE)] if isinstance(s, (int, float)) and isinstance(e, (int, float)) else []


def scan_running() -> bool:
    root = Path(os.environ.get("LG_PROC", "/proc"))
    try:
        entries = [p for p in root.iterdir() if p.name.isdigit()]
    except OSError:
        return False
    for p in entries:
        try:
            cmd = (p / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if any(prog in cmd for prog in SCAN_PROGRAMS) and "decoys.py" not in cmd:
            return True
    return False


def check() -> list[dict]:
    """Look for decoys that were read, changed or deleted since the last look. Re-arms after each look."""
    state = load_state()
    items = state.get("items", {})
    out = []
    t = now()
    windows = scan_windows()
    busy = scan_running()
    for p, meta in items.items():
        path = Path(p)
        try:
            st = os.lstat(path)
        except OSError:
            if not meta.get("gone"):
                meta["gone"] = True
                out.append({"event": "decoy_deleted", "path": p, "what": _what(meta), "key": f"decoy:del:{p}"})
            continue
        if meta.get("gone"):
            meta.pop("gone")                                   # it came back
        if st.st_ino != meta["ino"] or st.st_size != meta["size"] or st.st_mtime_ns != meta["mtime_ns"]:
            out.append({"event": "decoy_modified", "path": p, "what": _what(meta), "key": f"decoy:mod:{p}:{st.st_mtime_ns}"})
            meta.update(ino=st.st_ino, size=st.st_size, mtime_ns=st.st_mtime_ns)
            meta["armed_atime_ns"] = arm(path)
            continue
        if not state.get("atime_works", True):
            continue
        if st.st_atime_ns > meta["armed_atime_ns"]:
            when = st.st_atime
            ours = busy or any(a <= when <= b for a, b in windows)
            if not ours:
                out.append({"event": "decoy_read", "path": p, "what": _what(meta), "key": f"decoy:read:{p}:{int(when)}", "when": when})
            meta["armed_atime_ns"] = arm(path)
    state["last_check"] = t
    save_state(state)
    return out


def _what(meta: dict) -> str:
    return next((s["what"] for s in SPECS if s["id"] == meta.get("id")), "a decoy")


def status() -> dict:
    state = load_state()
    items = []
    for p, meta in state.get("items", {}).items():
        items.append({"path": p, "what": _what(meta), "exists": os.path.lexists(p)})
    return {"planted": bool(items), "items": items, "read_detection": state.get("atime_works"),
            "text": ("No decoys planted." if not items else
                     f"{len(items)} decoy file(s) planted" + ("" if state.get("atime_works", True) else
                                                               ", but this disk doesn't record when files are read, so only changes and deletions are noticed."))}


def message(f: dict) -> str:
    what = f["what"]
    if f["event"] == "decoy_read":
        return (f"The decoy file {f['path']} (fake {what}) was just opened. Nothing legitimate reads it, so a program or person may be searching "
                "your files for secrets. Backup tools and file indexers can also do this.")
    if f["event"] == "decoy_modified":
        return f"The decoy file {f['path']} (fake {what}) was changed. Nothing legitimate edits it."
    return f"The decoy file {f['path']} (fake {what}) was deleted. Something may be cleaning up after itself."


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    for flag in ("create", "status", "check", "remove"):
        g.add_argument(f"--{flag}", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.create:
        r = create()
        print(json.dumps(r) if a.json else f"Planted {len(r['created'])} decoy(s)." + ("" if r["read_detection"] else " Note: this disk doesn't update access times, so reads can't be detected.")
              + "".join(f"\n  skipped {s['path']}: {s['why']}" for s in r["skipped"]))
    elif a.status:
        s = status()
        print(json.dumps(s) if a.json else s["text"])
    elif a.check:
        r = check()
        print(json.dumps(r) if a.json else ("\n".join(message(f) for f in r) or "Nothing touched the decoys."))
    else:
        r = remove()
        print(json.dumps(r) if a.json else f"Removed {len(r['removed'])} decoy(s)." + (f" Left alone because they were changed since planting: {', '.join(r['kept'])}" if r["kept"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())

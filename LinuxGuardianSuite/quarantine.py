#!/usr/bin/env python3
"""Malware cleaner: isolate what a scan found, reversibly. Nothing is deleted unless you ask for exactly that.

The flow is deliberately cautious, because antivirus has false alarms (a ROS build, a model file, a security tool):

  findings    what the last ClamAV scan flagged, with a plain explanation of the signature name and a flag for the ones
              that are often false alarms
  verify      before moving anything the file is scanned AGAIN, because a scan report is text and a file name can be
              made to look like a report line
  quarantine  the file is copied into a private folder, its hash checked, made non-executable and read-only, and only
              then removed from where it was. Its origin, hash and the signature are kept so it can be put back
  restore     puts it back where it came from (not executable unless you ask), never over something that is there now
  delete      the only irreversible step, and only for something already in quarantine
  ignore      "this one is safe": hides it from the list (until the file changes)

Files that belong to an installed package are refused (reinstall the package instead), as are files you don't own.
After quarantining, anything that mentions the file (startup entries, cron, shell files) is listed so you can check for
persistence; this tool does not edit those.

  quarantine.py --findings [--json]
  quarantine.py --list [--json]
  quarantine.py --quarantine PATH [--signature NAME] [--skip-verify]
  quarantine.py --restore ID [--keep-executable]
  quarantine.py --delete ID
  quarantine.py --ignore PATH

Test hooks: LG_HOME, LG_SENSOR_HOME, LG_SENSOR_ETC, LG_PROC.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

import sensors  # noqa: E402
from events import lg_home, record_event  # noqa: E402

FOUND_LINE = re.compile(r"^(?P<path>/.+): (?P<sig>[^:]+?) FOUND$")
ID_RE = re.compile(r"[0-9a-f]{10}")
NEVER_UNDER = ("/proc/", "/sys/", "/dev/")
MAX_BYTES = 4 * 1024 ** 3
SCAN_TIMEOUT = 180


class QuarantineError(Exception):
    """Something the person can understand and act on."""


def quarantine_dir() -> Path:
    return lg_home() / "quarantine"


def ignore_path() -> Path:
    return lg_home() / "state" / "quarantine_ignore.json"


def clean_for_display(text: str) -> str:
    """File names are attacker-controlled: never show control characters."""
    return "".join(c if c.isprintable() else "?" for c in text)


# ========================================================== signatures
SIGNATURE_KINDS = [
    (re.compile(r"eicar", re.I), "test", True, "This is the harmless standard antivirus TEST file (EICAR). It isn't malware; it exists to check that scanners work."),
    (re.compile(r"^(?:[\w-]+\.)?Heuristics?\.|\.Heuristic[.-]|heuristic", re.I), "heuristic", True,
     "Flagged by a rule that looks for suspicious behaviour, not by matching a known sample. False alarms are common, especially on programs you built yourself."),
    (re.compile(r"^(?:Win|Doc|Xls|Ppt|Js|Html|Pdf|Osx|Andr|Legacy)\.", re.I), "foreign", True,
     "Malware for another system (Windows, Office documents, scripts, PDFs, Android). It can't run on Linux by itself; the risk is passing it on to someone else."),

    (re.compile(r"miner|xmrig|cryptominer", re.I), "miner", False, "A cryptocurrency miner: it burns your CPU/GPU to make money for someone else."),
    (re.compile(r"ransom", re.I), "ransomware", False, "Ransomware encrypts files and demands payment. Move it aside and check your files and backups."),
    (re.compile(r"^PUA\.", re.I), "pua", True,
     "A 'potentially unwanted application': adware, a bundled installer, or a tool that hackers also use (password crackers, scanners). Often something you installed on purpose."),
    (re.compile(r"backdoor|rootkit|trojan|rat\b|botnet|mirai|gafgyt|tsunami", re.I), "backdoor", False,
     "Software that lets someone else control the machine or use it in a botnet. If it is a Linux file, take it seriously."),
]


def explain_signature(sig: str) -> dict:
    """Plain words for a ClamAV signature name, and whether it is often a false alarm."""
    for rx, kind, fp, text in SIGNATURE_KINDS:
        if rx.search(sig):
            return {"kind": kind, "text": text, "often_false_alarm": fp}
    if re.match(r"^(?:Unix|Linux|Elf)\.", sig, re.I):
        return {"kind": "linux", "text": "Matches known malware built for Linux. Take it seriously, and check what else it did before you remove it.", "often_false_alarm": False}
    return {"kind": "generic", "text": "Matches a known malware signature. Check where the file came from before deciding.", "often_false_alarm": False}


# ============================================================ findings
def read_report(path: Path) -> list[dict]:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return []
    out, seen = [], set()
    for line in text.splitlines():
        m = FOUND_LINE.match(line.rstrip())
        if m and m["path"] not in seen:
            seen.add(m["path"])
            out.append({"path": m["path"], "signature": m["sig"].strip()})
    return out


def load_ignored() -> dict:
    try:
        d = json.loads(ignore_path().read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def sha256_file(path: str) -> str | None:
    h = hashlib.sha256()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def package_of(path: str) -> str:
    return sensors.package_owner(path)


def assess(path: str) -> dict:
    """Can this file be quarantined from here? {ok, reason}. Never changes anything."""
    p = Path(path)
    if not p.is_absolute() or "\0" in path or "\n" in path:
        return {"ok": False, "reason": "That isn't a usable file path."}
    if any(path.startswith(x) for x in NEVER_UNDER):
        return {"ok": False, "reason": "System files under /proc, /sys and /dev are never touched."}
    qd = str(quarantine_dir()) + "/"
    if path.startswith(qd) or path.startswith(str(lg_home()) + "/"):
        return {"ok": False, "reason": "That is LinuxGuardian's own data."}
    try:
        st = os.lstat(path)
    except OSError:
        return {"ok": False, "reason": "The file is no longer there."}
    if stat.S_ISLNK(st.st_mode):
        return {"ok": False, "reason": "This is a symbolic link. Check what it points to instead."}
    if not stat.S_ISREG(st.st_mode):
        return {"ok": False, "reason": "Only regular files can be quarantined."}
    if st.st_size > MAX_BYTES:
        return {"ok": False, "reason": "The file is too large to copy safely."}
    pkg = package_of(path)
    if pkg:
        return {"ok": False, "reason": f"This file belongs to the installed package '{pkg}'. Reinstall that package instead: sudo apt reinstall {pkg}", "package": pkg}
    if st.st_uid != os.getuid():
        return {"ok": False, "reason": "You don't own this file, so removing it needs administrator rights. Do it by hand: sudo mv the file somewhere safe, after checking it."}
    parent = os.path.dirname(path)
    if not os.access(parent, os.W_OK | os.X_OK):
        return {"ok": False, "reason": "You can't remove files from that folder."}
    return {"ok": True, "reason": ""}


def running_from(path: str) -> list[int]:
    return sorted(p["pid"] for p in sensors.iter_processes() if p["exe"].removesuffix(" (deleted)") == path)


def findings(report: Path | None = None) -> dict:
    """What the last scan flagged that is still here and not already handled."""
    try:
        last = json.loads((lg_home() / "scans" / "last.json").read_text())
    except (OSError, json.JSONDecodeError):
        last = {}
    last = last if isinstance(last, dict) else {}
    rpt = report or (Path(last["report"]) if last.get("report") else None)
    rows = read_report(rpt) if rpt else []
    ignored = load_ignored()
    items = []
    for r in rows:
        path = r["path"]
        if path.startswith(str(quarantine_dir()) + "/"):
            continue                                       # a clamd scan can walk into our own quarantine folder
        info = explain_signature(r["signature"])
        a = assess(path)
        if not os.path.lexists(path):
            continue                                       # already gone (removed, or the scan was of a temp file)
        digest = sha256_file(path)
        if digest and ignored.get(path, {}).get("sha256") == digest:
            continue
        items.append({"path": path, "shown": clean_for_display(path), "signature": r["signature"], **info, "can_quarantine": a["ok"],
                      "why_not": a["reason"], "running": running_from(path) if a["ok"] or a.get("package") else [], "sha256": digest})
    return {"scan_time": last.get("timestamp"), "report": str(rpt) if rpt else None, "infected_in_scan": last.get("infected"), "items": items}


# ============================================================ verify
def verify_infected(path: str) -> str | None:
    """Scan this one file again. The signature name if it is still detected, '' if clean, None if no scanner could run."""
    exe = shutil.which("clamdscan") or shutil.which("clamscan")
    if exe is None:
        return None
    cmd = [exe, "--no-summary"] + (["--fdpass"] if os.path.basename(exe) == "clamdscan" else []) + ["--", path]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode == 1:
        for line in r.stdout.splitlines():
            m = FOUND_LINE.match(line.strip())
            if m:
                return m["sig"].strip()
        return "(detected)"
    if r.returncode == 0:
        return ""
    return None


# =========================================================== references
def find_references(path: str) -> list[dict]:
    """Places that mention this file and could bring it back: startup entries, user services, cron, shell files. Report only."""
    h, e = sensors.home(), sensors.etc()
    base = os.path.basename(path)
    needles = [path] + ([base] if len(base) >= 6 else [])
    spots: list[Path] = []
    for d, pats in ((h / ".config/autostart", ("*.desktop",)), (h / ".config/systemd/user", ("*.service", "*.timer")), (e / "cron.d", ("*",)),
                    (e / "xdg/autostart", ("*.desktop",))):
        try:
            spots += [p for p in d.glob(pats[0]) if p.is_file()]
        except OSError:
            pass
    spots += [h / n for n in (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".xprofile")]
    out = []
    for p in spots:
        try:
            for line in p.read_text(errors="replace").splitlines():
                if any(n in line for n in needles):
                    out.append({"where": str(p), "line": clean_for_display(line.strip())[:200]})
                    break
        except OSError:
            continue
    rc, ct = sensors._run(["crontab", "-l"])
    if rc == 0:
        for line in ct.splitlines():
            if any(n in line for n in needles):
                out.append({"where": "your crontab", "line": clean_for_display(line.strip())[:200]})
                break
    return out


# ============================================================ actions
def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    tmp.replace(path)


def quarantine(path: str, signature: str = "", verify: bool = True) -> dict:
    """Move one file into quarantine. Reversible. Raises QuarantineError with a plain reason if it must not."""
    a = assess(path)
    if not a["ok"]:
        raise QuarantineError(a["reason"])
    if verify:
        sig = verify_infected(path)
        if sig is None:
            raise QuarantineError("ClamAV isn't available to double-check the file, so it was left alone. (Install clamav, or use --skip-verify if you are sure.)")
        if sig == "":
            raise QuarantineError("A second scan found nothing wrong with this file, so it was left alone. The report may have been out of date or misleading.")
        signature = signature or sig
    try:
        src_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise QuarantineError(f"Can't open the file ({exc.strerror}).") from exc
    qid = secrets.token_hex(5)
    dest_dir = quarantine_dir() / qid
    try:
        st = os.fstat(src_fd)
        if not stat.S_ISREG(st.st_mode):
            raise QuarantineError("Only regular files can be quarantined.")
        quarantine_dir().mkdir(parents=True, exist_ok=True)
        os.chmod(quarantine_dir(), 0o700)
        dest_dir.mkdir(mode=0o700)
        payload = dest_dir / "payload"
        h = hashlib.sha256()
        out_fd = os.open(payload, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(src_fd, "rb", closefd=False) as src, os.fdopen(out_fd, "wb") as dst:
            for chunk in iter(lambda: src.read(1024 * 1024), b""):
                h.update(chunk)
                dst.write(chunk)
        copied = sha256_file(str(payload))
        if copied != h.hexdigest():
            raise QuarantineError("The copy didn't match the original, so nothing was moved.")
        os.chmod(payload, 0o400)                            # not executable, not writable
        meta = {"id": qid, "original_path": path, "name": os.path.basename(path), "sha256": h.hexdigest(), "size": st.st_size,
                "mode": stat.S_IMODE(st.st_mode), "mtime": st.st_mtime, "signature": signature, "time": time.time()}
        _write_private(dest_dir / "meta.json", json.dumps(meta))
        # Remove the original only if it is still the very same file we copied (not something swapped in meanwhile).
        now = os.lstat(path)
        if (now.st_ino, now.st_dev) != (st.st_ino, st.st_dev):
            raise QuarantineError("The file changed while it was being moved, so it was left alone.")
        os.unlink(path)
    except QuarantineError:
        shutil.rmtree(dest_dir, ignore_errors=True)
        raise
    except OSError as exc:
        shutil.rmtree(dest_dir, ignore_errors=True)
        raise QuarantineError(f"Couldn't move the file ({exc.strerror}); nothing was changed.") from exc
    finally:
        try:
            os.close(src_fd)
        except OSError:
            pass
    refs = find_references(path)
    record_event("malware", "info", "file_quarantined", f"Moved {clean_for_display(os.path.basename(path))} to quarantine"
                 + (f" ({signature})" if signature else "") + ".", id=qid, path=path, signature=signature)
    return {"id": qid, "original_path": path, "signature": signature, "references": refs, "running": running_from(path)}


def list_items() -> list[dict]:
    root = quarantine_dir()
    out = []
    if not root.is_dir():
        return out
    for d in root.iterdir():
        if not (d.is_dir() and ID_RE.fullmatch(d.name)):
            continue
        try:
            meta = json.loads((d / "meta.json").read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(meta, dict) or meta.get("id") != d.name or not (d / "payload").is_file():
            continue
        meta["shown"] = clean_for_display(str(meta.get("original_path", "")))
        meta.update(explain_signature(str(meta.get("signature", ""))))
        out.append(meta)
    return sorted(out, key=lambda m: -float(m.get("time", 0)))


def _item(qid: str) -> dict:
    if not ID_RE.fullmatch(qid or ""):
        raise QuarantineError("No such quarantined item.")
    for m in list_items():
        if m["id"] == qid:
            return m
    raise QuarantineError("No such quarantined item.")


def restore(qid: str, keep_executable: bool = False) -> dict:
    m = _item(qid)
    target = m["original_path"]
    payload = quarantine_dir() / qid / "payload"
    if sha256_file(str(payload)) != m["sha256"]:
        raise QuarantineError("The quarantined copy no longer matches its saved hash (it was changed). It was not restored.")
    if os.path.lexists(target):
        raise QuarantineError("Something already exists at the original location, so nothing was overwritten.")
    parent = os.path.dirname(target)
    if not os.path.isdir(parent) or not os.access(parent, os.W_OK | os.X_OK):
        raise QuarantineError("The original folder is gone or isn't writable.")
    mode = int(m.get("mode", 0o644))
    if not keep_executable:
        mode &= ~0o111
    tmp = os.path.join(parent, f".lg-restore-{secrets.token_hex(4)}")
    try:
        shutil.copyfile(payload, tmp)
        os.chmod(tmp, mode)
        os.link(tmp, target)                                # fails if something appeared meanwhile: never overwrites
    except OSError as exc:
        raise QuarantineError(f"Couldn't put the file back ({exc.strerror}).") from exc
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    shutil.rmtree(quarantine_dir() / qid, ignore_errors=True)
    record_event("malware", "info", "file_restored", f"Restored {clean_for_display(os.path.basename(target))} from quarantine.", id=qid, path=target)
    return {"id": qid, "path": target, "executable": keep_executable}


def delete(qid: str) -> dict:
    m = _item(qid)
    shutil.rmtree(quarantine_dir() / qid)
    record_event("malware", "info", "quarantine_deleted", f"Permanently deleted {clean_for_display(m['name'])} from quarantine.", id=qid, path=m["original_path"])
    return {"id": qid}


def ignore(path: str) -> dict:
    digest = sha256_file(path)
    if digest is None or not os.path.isabs(path):
        raise QuarantineError("Can't read that file to remember it.")
    d = load_ignored()
    d[path] = {"sha256": digest, "time": time.time()}
    _write_private(ignore_path(), json.dumps(d))
    return {"path": path}


# ================================================================== CLI
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--findings", action="store_true")
    g.add_argument("--list", action="store_true")
    g.add_argument("--quarantine", metavar="PATH")
    g.add_argument("--restore", metavar="ID")
    g.add_argument("--delete", metavar="ID")
    g.add_argument("--ignore", metavar="PATH")
    ap.add_argument("--signature", default="")
    ap.add_argument("--skip-verify", action="store_true")
    ap.add_argument("--keep-executable", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    try:
        if a.findings:
            r = findings()
            if a.json:
                print(json.dumps(r))
            else:
                for i in r["items"]:
                    print(f"{i['shown']}: {i['signature']}" + ("" if i["can_quarantine"] else f"  [not movable: {i['why_not']}]"))
                if not r["items"]:
                    print("Nothing from the last scan needs attention.")
        elif a.list:
            items = list_items()
            if a.json:
                print(json.dumps(items))
            else:
                for m in items:
                    print(f"{m['id']}  {m['shown']}  {m.get('signature', '')}")
                if not items:
                    print("Quarantine is empty.")
        elif a.quarantine:
            r = quarantine(a.quarantine, a.signature, verify=not a.skip_verify)
            print(json.dumps(r) if a.json else f"Moved to quarantine as {r['id']}. Restore with: {Path(__file__).resolve()} --restore {r['id']}")
        elif a.restore:
            r = restore(a.restore, a.keep_executable)
            print(json.dumps(r) if a.json else f"Restored to {r['path']}" + ("" if r["executable"] else " (not executable)."))
        elif a.delete:
            delete(a.delete)
            print("Deleted permanently.")
        else:
            ignore(a.ignore)
            print("OK: this file will no longer be listed (until it changes).")
    except QuarantineError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

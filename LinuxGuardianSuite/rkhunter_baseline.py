#!/usr/bin/env python3
"""Can rkhunter's baseline be refreshed safely? (read-only analysis, no root)

rkhunter compares system files with a stored baseline. Ubuntu doesn't refresh that baseline
after package updates, so a real run reports many "file properties have changed" warnings that
are just updates. Refreshing the baseline (`rkhunter --propupd`) makes rkhunter accept the
system as it is now, so doing it on a compromised system would hide the compromise.

This checks the last rootkit scan's warnings against the one thing that can vouch for a file:
its Ubuntu package. A changed file is EXPLAINED only if it belongs to an installed package and
still matches that package's checksums (`dpkg --verify`). The baseline is offered for refresh
only when EVERY warning is explained. Anything else (a file no package owns, a file that
differs from its package, a non-file warning, a count that doesn't add up) blocks it.

  rkhunter_baseline.py [--log PATH] [--json|--text]

Exit: 0 safe to refresh, 3 not safe / nothing to refresh, 1 couldn't analyze.
Test hooks: LG_HOME. dpkg is found on PATH.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

from events import lg_home  # noqa: E402
from scan_store import rootkit_check_status, rkhunter_warning_count  # noqa: E402

_PATH_WARNING = re.compile(r"^[\t ]*(/\S+)\s+\[\s*Warning\s*\]\s*$", re.M)
_LOG_STYLE_FILE = re.compile(r"^[\t ]*File:\s*(/\S+)", re.M)
_SUSPECT = re.compile(r"^[\t ]*Suspect files\s*:\s*(\d+)", re.M | re.I)


def _run(cmd: list[str], timeout: float = 120) -> tuple[int, str, str]:
    env = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)
    return p.returncode, p.stdout, p.stderr


def default_log() -> Path | None:
    try:
        data = json.loads((lg_home() / "scans" / "last.json").read_text())
        report = data.get("rk_report")
        return Path(report) if report else None
    except (OSError, json.JSONDecodeError, AttributeError):
        return None


def changed_files(text: str) -> list[str]:
    found = _PATH_WARNING.findall(text)
    if not found:
        found = _LOG_STYLE_FILE.findall(text)
    seen: dict[str, None] = {}
    for f in found:
        seen.setdefault(f)
    return list(seen)


def package_owners(paths: list[str]) -> dict[str, str]:
    """path -> package, for the paths dpkg knows. Unknown paths are simply absent."""
    owners: dict[str, str] = {}
    if not paths:
        return owners
    _rc, out, _err = _run(["dpkg", "-S", "--", *paths])
    for line in out.splitlines():
        pkgs, sep, path = line.partition(": ")
        if sep and path in paths:
            owners[path] = pkgs.split(",")[0].strip().split(":")[0]
    return owners


def modified_paths(packages: list[str]) -> tuple[set[str], bool]:
    """(paths that differ from their package, whether verification was complete)."""
    if not packages:
        return set(), True
    rc, out, err = _run(["dpkg", "--verify", "--", *sorted(set(packages))], timeout=300)
    bad = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].startswith("/"):
            bad.add(parts[-1])
    complete = rc in (0, 1) and "unable" not in err.lower() and "permission denied" not in err.lower()
    return bad, complete


def analyze(log_path: Path | None) -> dict:
    result = {
        "ok": False, "safe_to_refresh": False, "reason": "", "log": str(log_path) if log_path else None,
        "total_warnings": 0, "files": [], "explained": 0, "unexplained": 0, "other_warnings": 0,
    }
    if log_path is None or not log_path.is_file():
        result["reason"] = "No rootkit scan on file yet. Run a scan with the rootkit check first."
        return result
    if rootkit_check_status(log_path) != "ran":
        result["reason"] = "The last rootkit check didn't run, so there is nothing to compare."
        return result
    text = log_path.read_text(errors="replace")
    total = rkhunter_warning_count(log_path)
    files = changed_files(text)
    suspect = max((int(m) for m in _SUSPECT.findall(text)), default=0)
    result.update(ok=True, total_warnings=total)
    if total == 0:
        result["reason"] = "rkhunter reported no warnings, so there is nothing to refresh."
        return result

    owners = package_owners(files)
    modified, complete = modified_paths(list(owners.values()))
    rows = []
    for f in files:
        pkg = owners.get(f)
        if pkg is None:
            rows.append({"path": f, "package": None, "explained": False, "why": "not owned by any installed package"})
        elif f in modified:
            rows.append({"path": f, "package": pkg, "explained": False, "why": f"differs from the {pkg} package"})
        elif not complete:
            rows.append({"path": f, "package": pkg, "explained": False, "why": "couldn't verify against its package"})
        else:
            rows.append({"path": f, "package": pkg, "explained": True, "why": f"matches the {pkg} package"})
    explained = sum(r["explained"] for r in rows)
    # Warnings we can't attribute to a specific file: anything beyond the file list.
    other = max(0, total - len(files), suspect - len(files))
    result.update(files=rows, explained=explained, unexplained=len(rows) - explained, other_warnings=other)

    if other:
        result["reason"] = (f"{other} warning(s) are not about changed files (or couldn't be matched to a file). "
                            "Look at those first: refreshing the baseline would not be safe.")
    elif not rows:
        result["reason"] = "Warnings were reported but no changed files could be identified, so none can be checked."
    elif result["unexplained"]:
        result["reason"] = (f"{result['unexplained']} changed file(s) are NOT explained by a package update. "
                            "Investigate those before refreshing anything.")
    else:
        result["safe_to_refresh"] = True
        result["reason"] = f"All {len(rows)} changed file(s) still match their Ubuntu packages: this is just updates."
    return result


def render_text(r: dict) -> str:
    lines = [r["reason"]]
    for row in r["files"]:
        lines.append(f"  {'ok ' if row['explained'] else 'NO '} {row['path']}  ({row['why']})")
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--log", type=Path)
    p.add_argument("--json", action="store_true")
    p.add_argument("--text", action="store_true")
    a = p.parse_args()
    r = analyze(a.log or default_log())
    print(json.dumps(r) if a.json else render_text(r))
    if not r["ok"]:
        return 1
    return 0 if r["safe_to_refresh"] else 3


if __name__ == "__main__":
    sys.exit(main())

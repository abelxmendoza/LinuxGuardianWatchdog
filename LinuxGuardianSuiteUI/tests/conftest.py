"""Shared test hygiene.

Some tests deliberately create setuid/setgid files (the setuid sensor has to be tested against them). pytest keeps the last few
temporary folders under /tmp, and the LIVE setuid sensor on this laptop walks /tmp every six hours: leftovers there are reported
as critical findings. So the fixtures strip the bits when they finish, and this session hook strips anything that slipped through.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


def strip_special_bits(root: Path) -> int:
    """Remove setuid/setgid from every regular file under root. Returns how many files needed it. Never follows symlinks."""
    n = 0
    for dirpath, _dirs, files in os.walk(root, followlinks=False):
        for name in files:
            p = os.path.join(dirpath, name)
            try:
                st = os.lstat(p)
                if stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    os.chmod(p, stat.S_IMODE(st.st_mode) & ~(stat.S_ISUID | stat.S_ISGID))
                    n += 1
            except OSError:
                pass
    return n


def pytest_sessionfinish(session, exitstatus):
    factory = getattr(session.config, "_tmp_path_factory", None)
    if factory is None:
        return
    try:
        base = Path(factory.getbasetemp())
    except Exception:  # noqa: BLE001 - hygiene must never fail a test run
        return
    n = strip_special_bits(base.parent)             # every retained run folder, not just this one
    if n:
        print(f"\n[conftest] {n} test file(s) still had setuid/setgid bits; removed them so the live sensor won't flag them.", file=sys.stderr)

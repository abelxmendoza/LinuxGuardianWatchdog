"""Shared test hygiene.

Some tests deliberately create setuid/setgid files (the setuid sensor has to be tested against them). pytest keeps the last few
temporary folders under /tmp, and the LIVE setuid sensor on this laptop walks /tmp every six hours: leftovers there are reported
as critical findings. So the fixtures strip the bits when they finish, and this session hook strips anything that slipped through.
"""
from __future__ import annotations

import atexit
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path


def pytest_configure(config):
    """Aim the whole test session at a throwaway home BEFORE any test module is imported (several modules read HOME or LG_HOME when they are
    imported). A test that forgets to point at its own temp folder then lands here instead of in your real ~/.linuxguardian.
    Set LG_TEST_REAL_HOME=1 to opt out (nothing in the suite needs it)."""
    if os.environ.get("LG_TEST_REAL_HOME") == "1" or os.environ.get("LG_TEST_ISOLATED") == "1":
        return
    root = Path(tempfile.mkdtemp(prefix="lg-test-home-"))
    os.environ["LG_TEST_ISOLATED"] = "1"
    os.environ["LG_TEST_REAL_HOME_WAS"] = os.environ.get("HOME", "")
    for var, rel in (("HOME", "home"), ("LG_HOME", "home/.linuxguardian"), ("XDG_CONFIG_HOME", "home/.config"), ("XDG_DATA_HOME", "home/.local/share"),
                     ("XDG_CACHE_HOME", "home/.cache")):
        path = root / rel
        path.mkdir(parents=True, exist_ok=True)
        os.environ[var] = str(path)
    (root / "home" / ".linuxguardian").chmod(0o700)
    (root / "proc").mkdir()
    os.environ["LG_PROC"] = str(root / "proc")          # an empty /proc: no test depends on what happens to be running on the host
    (root / "journal.txt").write_text("")
    os.environ["LG_LOGIN_JOURNAL"] = str(root / "journal.txt")   # an empty journal: the host's real logins never reach a test
    atexit.register(shutil.rmtree, root, ignore_errors=True)


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

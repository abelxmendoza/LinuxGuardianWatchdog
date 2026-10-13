"""The test suite must not leave behind anything the live security monitor would call an incident."""
from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

from conftest import strip_special_bits

TESTS = Path(__file__).resolve().parent


def find_setuid(root: Path) -> list[str]:
    out = []
    for dp, _d, files in os.walk(root, followlinks=False):
        for f in files:
            p = os.path.join(dp, f)
            st = os.lstat(p)
            if stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                out.append(p)
    return out


def test_strip_special_bits_clears_setuid_and_setgid_and_nothing_else(tmp_path):
    a, b, c = tmp_path / "a", tmp_path / "sub" / "b", tmp_path / "c"
    (tmp_path / "sub").mkdir()
    for p, m in ((a, 0o4755), (b, 0o2750), (c, 0o640)):
        p.write_text("x")
        p.chmod(m)
    (tmp_path / "link").symlink_to(a)
    assert strip_special_bits(tmp_path) == 2
    assert stat.S_IMODE(a.stat().st_mode) == 0o755 and stat.S_IMODE(b.stat().st_mode) == 0o750 and stat.S_IMODE(c.stat().st_mode) == 0o640
    assert strip_special_bits(tmp_path) == 0


def test_running_the_setuid_tests_leaves_no_setuid_file_behind(tmp_path):
    """The regression that matters: after the setuid test module has run, its temp folder holds no setuid files."""
    base = tmp_path / "bt"
    r = subprocess.run([sys.executable, "-m", "pytest", str(TESTS / "test_setuid_watch.py"), "-q", "-x", "-p", "no:cacheprovider",
                        f"--basetemp={base}", "--no-header"], capture_output=True, text=True, cwd=TESTS.parent)
    assert r.returncode == 0, r.stdout[-800:]
    assert base.is_dir() and find_setuid(base) == []


def test_the_session_hook_also_catches_files_a_fixture_forgot(tmp_path):
    leaky = tmp_path / "test_leaky.py"
    leaky.write_text("import os\ndef test_leak(tmp_path):\n    p = tmp_path / 'su'\n    p.write_text('x')\n    p.chmod(0o4755)\n")
    (tmp_path / "conftest.py").write_text((TESTS / "conftest.py").read_text())
    base = tmp_path / "bt"
    r = subprocess.run([sys.executable, "-m", "pytest", str(leaky), "-q", "-p", "no:cacheprovider", f"--basetemp={base}", "--no-header"],
                       capture_output=True, text=True, cwd=tmp_path)
    assert r.returncode == 0 and find_setuid(base) == []
    assert "removed them" in r.stderr + r.stdout

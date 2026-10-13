"""Terminal fallback: every action is a fixed, valid command; only validated values get filled in; opening a terminal runs exactly that."""
from __future__ import annotations

import os
import re
import shlex
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import fallback as fb  # noqa: E402

SUITE = ROOT / "LinuxGuardianSuite"


def stub_terminal(tmp: Path, out: Path) -> Path:
    """A 'terminal' that skips its own flag and runs the rest, with output captured and stdin closed."""
    p = tmp / "faketerm"
    p.write_text(f'#!/bin/sh\nshift\n"$@" > "{out}" 2>&1 < /dev/null\n')
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p


# ------------------------------------------------------------------ the list
def test_ids_are_unique_and_complete():
    ids = [a["id"] for a in fb.ACTIONS]
    assert len(ids) == len(set(ids)) and len(ids) >= 25
    for a in fb.ACTIONS:
        assert a["title"] and a["what"] and a["group"] and (a["app"] or a["plain"]), a["id"]


def test_every_app_command_points_at_a_real_executable_script():
    for a in fb.ACTIONS:
        if not a["app"]:
            continue
        first = a["app"].split()[0].replace("{S}", str(SUITE))
        p = Path(first)
        assert p.is_file(), f"{a['id']}: {first} missing"
        assert os.access(p, os.X_OK), f"{a['id']}: {first} isn't executable"


def test_every_command_is_valid_shell_syntax():
    for row in fb.listing():
        for cmd in (row["app_command"], row["plain_command"]):
            if cmd:
                cmd = re.sub(r"<[^>]+>", "X", cmd)                              # a placeholder stands for a value
                r = subprocess.run(["bash", "-n", "-c", cmd], capture_output=True, text=True)
                assert r.returncode == 0, f"{row['id']}: {cmd}: {r.stderr}"


def test_the_fixed_list_never_contains_destructive_commands():
    banned = re.compile(r"\brm\b|\bdd\b|\bmkfs|\bshred\b|\bchmod\b|\bchown\b|\bwget\b|\|\s*(?:ba)?sh\b|\bcurl\b[^|]*\|\s*(?:ba)?sh|(?<!2)>\s*/(?!dev/null)|\beval\b|\bsource\b")
    for row in fb.listing():
        for cmd in (row["app_command"], row["plain_command"]):
            if cmd:
                assert not banned.search(cmd), f"{row['id']}: {cmd}"


def test_password_and_change_flags_match_the_command():
    for row in fb.listing():
        assert row["plain_password"] == bool(row["plain_command"] and "sudo" in row["plain_command"]), row["id"]
        if row["app_command"] and "sudo" in row["app_command"]:
            assert row["password"], row["id"]
        if row["plain_command"] and re.search(r"(?<![\w-])(?:kill|freshclam|unattended-upgrade|apt-get install)(?![\w-])", row["plain_command"]):
            assert row["safety"] == fb.CHANGE, row["id"]


def test_read_only_actions_dont_contain_changing_verbs():
    for row in fb.listing():
        if row["safety"] == fb.READ:
            text = " ".join(c for c in (row["app_command"], row["plain_command"]) if c)
            assert not re.search(r"--apply\b(?!\s+--dry-run)|--kill|--update\b|--restore|--clean\b|(?<![\w-])freshclam(?![\w-])|\bkill\b", text), row["id"]


def test_listing_uses_placeholders_but_show_needs_a_valid_value():
    rows = {r["id"]: r for r in fb.listing()}
    assert "<process id>" in rows["stop_process"]["plain_command"] and rows["stop_process"]["needs_param"] == "pid"
    assert "<id>" in rows["evidence"]["app_command"]
    with pytest.raises(fb.FallbackError):
        fb.commands("stop_process")
    with pytest.raises(fb.FallbackError):
        fb.commands("nope")


@pytest.mark.parametrize("bad", ["", "0", "-1", "12 34", "1;rm -rf ~", "$(id)", "`id`", "4242\n", "1e3", "٤٢", "9" * 12, "../1", "4242 &"])
def test_bad_process_ids_are_refused(bad):
    with pytest.raises(fb.FallbackError):
        fb.commands("stop_process", bad)


@pytest.mark.parametrize("bad", ["", "zz", "abc", "../../x", "abcdef; ls", "ABCDEF12", "abcdef12 --x"])
def test_bad_incident_ids_are_refused(bad):
    with pytest.raises(fb.FallbackError):
        fb.commands("evidence", bad)


def test_valid_values_are_filled_in_and_quoted():
    assert fb.commands("stop_process", "4242")["plain_command"] == "kill 4242"
    assert fb.commands("evidence", "a1b2c3d4e5")["app_command"].endswith("evidence.py --incident a1b2c3d4e5")


def test_a_suite_folder_with_spaces_still_forms_one_word(monkeypatch, tmp_path):
    d = tmp_path / "my suite (v2)"
    d.mkdir()
    monkeypatch.setattr(fb, "SUITE_DIR", d)
    cmd = fb.commands("scan")["app_command"]
    assert shlex.split(cmd)[0] == str(d / "linux_guardian.sh") and shlex.split(cmd)[1] == "--scan"


def test_there_is_a_plain_tools_version_for_the_essentials():
    have = {a["id"] for a in fb.ACTIONS if a["plain"]}
    assert {"scan", "scan_rootkit", "definitions", "updates_check", "exposure", "connections", "firewall", "processes", "stop_process", "failed_logins"} <= have


# ------------------------------------------------------------------ terminal
def test_opening_runs_exactly_the_listed_command_in_a_terminal(monkeypatch, tmp_path):
    out = tmp_path / "out.txt"
    monkeypatch.setenv("LG_TERMINAL", str(stub_terminal(tmp_path, out)))
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    ok, msg = fb.open_in_terminal("incidents")
    assert ok and "terminal" in msg
    for _ in range(100):
        if out.exists() and "Finished" in out.read_text():
            break
        time.sleep(0.1)
    text = out.read_text()
    assert "No open incidents." in text and "Finished (exit code 0)" in text


def test_the_plain_command_can_be_opened_instead(monkeypatch, tmp_path):
    out = tmp_path / "out.txt"
    monkeypatch.setenv("LG_TERMINAL", str(stub_terminal(tmp_path, out)))
    ok, _ = fb.open_in_terminal("recent_logins", which="plain")
    assert ok
    for _ in range(100):
        if out.exists() and "Finished" in out.read_text():
            break
        time.sleep(0.1)
    assert "Finished (exit code" in out.read_text()


def test_the_terminal_gets_a_login_bash_with_a_pause_at_the_end(monkeypatch, tmp_path):
    seen = {}

    class P:
        def __init__(self, argv, **kw):
            seen["argv"], seen["kw"] = argv, kw

    monkeypatch.setattr(fb.subprocess, "Popen", P)
    monkeypatch.setenv("LG_TERMINAL", str(stub_terminal(tmp_path, tmp_path / "o")))
    ok, _ = fb.open_in_terminal("stop_process", param="4242")
    argv = seen["argv"]
    assert ok and argv[1:4] == ["-e", "bash", "-lc"] and argv[4].startswith("/") and "--kill 4242;" in argv[4] and "Press Enter to close" in argv[4] and argv[4].endswith("read -r _")
    assert seen["kw"]["start_new_session"] is True


def test_open_refuses_bad_input_and_missing_pieces(monkeypatch, tmp_path):
    monkeypatch.setenv("LG_TERMINAL", str(stub_terminal(tmp_path, tmp_path / "o")))
    assert fb.open_in_terminal("stop_process", param="1; reboot")[0] is False
    assert fb.open_in_terminal("no_such_action")[0] is False
    assert fb.open_in_terminal("connections", which="app")[0] is False                    # no app command for it
    monkeypatch.setenv("LG_TERMINAL", str(tmp_path / "missing"))
    ok, msg = fb.open_in_terminal("incidents")
    assert not ok and "Copy the command" in msg


def test_terminal_search_prefers_gnome_and_knows_each_flag(monkeypatch, tmp_path):
    monkeypatch.delenv("LG_TERMINAL", raising=False)
    for name in ("konsole", "xterm"):
        p = tmp_path / name
        p.write_text("#!/bin/sh\n")
        p.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert fb.find_terminal()[0].endswith("konsole") and fb.find_terminal()[1] == ["-e"]
    g = tmp_path / "gnome-terminal"
    g.write_text("#!/bin/sh\n")
    g.chmod(0o755)
    assert fb.find_terminal() == (str(g), ["--"])
    monkeypatch.setenv("PATH", "/nonexistent")
    assert fb.find_terminal() is None


def test_nothing_in_the_module_runs_arbitrary_text(monkeypatch, tmp_path):
    """Opening is only possible by action id: there is no function that takes a command string from outside."""
    src = (SUITE / "fallback.py").read_text()
    assert "shell=True" not in src
    import inspect
    assert list(inspect.signature(fb.open_in_terminal).parameters) == ["aid", "which", "param"]


def test_cli_list_show_and_open(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sys, "argv", ["fallback.py", "--list"])
    assert fb.main() == 0 and "scan_rootkit" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["fallback.py", "--show", "stop_process", "--param", "7"])
    assert fb.main() == 0 and "kill 7" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["fallback.py", "--show", "stop_process", "--param", "x"])
    assert fb.main() == 1 and "process id" in capsys.readouterr().err

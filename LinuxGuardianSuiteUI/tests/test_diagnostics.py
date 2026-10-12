"""Diagnostics: each feature says whether it works, and what is missing when it doesn't."""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import diagnostics as dg  # noqa: E402


def make_path(tmp: Path, tools: list[str]) -> str:
    b = tmp / "bin"
    b.mkdir(exist_ok=True)
    for t in tools:
        p = b / t
        p.write_text("#!/bin/sh\nexit 0\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(b)


@pytest.fixture()
def lg(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    return tmp_path


def feature(report: dict, name: str) -> dict:
    return {f["feature"]: f for f in report["features"]}[name]


def test_all_tools_present_means_every_feature_ready(lg, monkeypatch):
    monkeypatch.setenv("PATH", make_path(lg, list(dg.TOOLS)))
    r = dg.collect(include_scripts=False)
    assert all(f["status"] == "ready" for f in r["features"] if "pkexec" not in dg.FEATURES[f["feature"]])


def test_a_missing_essential_tool_makes_only_the_features_that_need_it_unavailable(lg, monkeypatch):
    monkeypatch.setenv("PATH", make_path(lg, [t for t in dg.TOOLS if t != "rkhunter"]))
    r = dg.collect(include_scripts=False)
    rk = feature(r, "Rootkit check")
    assert rk["status"] == "unavailable" and rk["missing"] == ["rkhunter"] and "apt install rkhunter" in rk["hints"][0]
    assert feature(r, "Malware scan")["status"] != "unavailable"


def test_a_missing_optional_tool_only_limits(lg, monkeypatch):
    monkeypatch.setenv("PATH", make_path(lg, [t for t in dg.TOOLS if t != "notify-send"]))
    r = dg.collect(include_scripts=False)
    assert feature(r, "Notifications")["status"] == "limited"              # optional tool: degraded, not broken
    assert dg.TOOLS["notify-send"][2] is False


def test_status_limited_when_the_missing_tool_is_not_essential():
    tools = [{"name": n, "found": n != "snap", "path": "", "needed_for": [], "hint": "", "essential": dg.TOOLS[n][2]} for n in dg.TOOLS]
    dg.FEATURES["__t"] = ("snap",)
    try:
        assert dg.features_report(tools)[-1]["status"] == "limited"
    finally:
        del dg.FEATURES["__t"]


def test_every_feature_only_names_known_tools():
    for feature_name, needs in dg.FEATURES.items():
        assert all(n in dg.TOOLS for n in needs), feature_name


def test_every_tool_says_what_it_is_for_and_how_to_get_it():
    for name, (needed_for, hint, _essential) in dg.TOOLS.items():
        assert needed_for and hint, name


def test_no_password_agent_makes_password_features_limited(lg, monkeypatch):
    monkeypatch.setenv("PATH", make_path(lg, list(dg.TOOLS) + ["pgrep"]))
    (lg / "bin/pgrep").write_text("#!/bin/sh\nexit 1\n")                      # nothing running: no gnome-shell, no agent
    r = dg.collect(include_scripts=False)
    env = {e["id"]: e for e in r["environment"]}
    assert env["polkit_agent"]["state"] == "problem" and "silently" in env["polkit_agent"]["detail"]
    assert feature(r, "Rootkit check")["status"] == "limited" and "polkit agent" in feature(r, "Rootkit check")["missing"]
    assert feature(r, "Malware scan")["status"] == "ready"                   # doesn't need a password
    assert not r["healthy"]


def test_unwritable_data_dir_is_a_problem(lg, monkeypatch):
    monkeypatch.setenv("PATH", make_path(lg, list(dg.TOOLS)))
    blocker = lg / "blocked"
    blocker.write_text("a file, not a directory")
    monkeypatch.setenv("LG_HOME", str(blocker / "sub"))
    env = {e["id"]: e for e in dg.environment_report()}
    assert env["data_dir"]["state"] == "problem" and env["data_dir"]["hint"]


def test_unscheduled_protection_is_a_note_with_the_fix(lg, monkeypatch):
    monkeypatch.setenv("PATH", make_path(lg, ["systemctl"]))
    (lg / "bin/systemctl").write_text("#!/bin/sh\necho disabled\nexit 1\n")
    env = {e["id"]: e for e in dg.environment_report()}
    assert env["scheduler"]["state"] == "note" and "install_scheduler.sh" in env["scheduler"]["hint"]


def test_script_integrity_check_catches_a_broken_script(tmp_path, monkeypatch):
    suite = tmp_path / "suite"
    suite.mkdir()
    good = suite / "good.sh"
    good.write_text("#!/bin/bash\necho hi\n")
    good.chmod(0o755)
    bad = suite / "bad.sh"
    bad.write_text("#!/bin/bash\nif then fi (\n")
    bad.chmod(0o755)
    noexec = suite / "noexec.sh"
    noexec.write_text("#!/bin/bash\necho\n")
    (suite / "broken.py").write_text("def (:\n")
    monkeypatch.setattr(dg, "SUITE_DIR", suite)
    r = dg.scripts_report()
    assert r["checked"] == 4 and set(r["broken"]) == {"bad.sh", "noexec.sh (not executable)", "broken.py"}


def test_the_real_install_is_intact():
    assert dg.scripts_report()["broken"] == []


def test_render_text_names_the_missing_pieces(lg, monkeypatch):
    monkeypatch.setenv("PATH", make_path(lg, [t for t in dg.TOOLS if t != "ufw"]))
    text = dg.render_text(dg.collect(include_scripts=False))
    assert "Firewall helper" in text and "ufw" in text and "sudo apt install ufw" in text and "needs attention" in text

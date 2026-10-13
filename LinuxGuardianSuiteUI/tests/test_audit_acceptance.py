"""Risk acceptance and the audit end to end: a risk you chose to live with stops nagging, a firewall that is on is never reported as off,
and nothing accepted can hide a different problem."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "LinuxGuardianSuite"
sys.path.insert(0, str(SUITE))

import audit_events as ae  # noqa: E402
import events  # noqa: E402
import notify_events as ne  # noqa: E402
import timeline as tl  # noqa: E402

LUKS = "No LUKS-encrypted volume detected — consider full-disk encryption"
UPDATES = "7 security update(s) pending — install them from the Updates tab"


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    (tmp_path / "lg" / "incidents").mkdir(parents=True)
    return tmp_path


def recorded() -> list[dict]:
    return events.read_events(limit=200)


# --------------------------------------------------------------------- acceptance
def test_an_accepted_finding_is_never_announced_again(home):
    ae.accept(LUKS)
    assert ae.process([("warning", LUKS)]) == (0, 0)
    assert [e for e in recorded() if e["event"] == "audit_finding"] == []
    assert ae.process([("warning", LUKS)]) == (0, 0)


def test_acceptance_leaves_an_audit_trail_and_survives_the_count_changing(home):
    ae.accept(UPDATES)
    [e] = [e for e in recorded() if e["event"] == "risk_accepted"]
    assert e["severity"] == "info" and e["message"].startswith("Accepted risk: 7 security update(s) pending")
    assert ae.process([("warning", "12 security update(s) pending — install them from the Updates tab")]) == (0, 0)   # same finding, new count
    assert ae.is_accepted("3 security update(s) pending") is True


def test_accepting_one_finding_never_hides_another(home):
    ae.accept(LUKS)
    new, _ = ae.process([("warning", LUKS), ("critical", "No active firewall detected — enable ufw: sudo ufw enable"), ("warning", UPDATES)])
    assert new == 2
    assert {e["message"].split(" — ")[0] for e in recorded() if e["event"] == "audit_finding"} == {"No active firewall detected", "7 security update(s) pending"}


def test_an_accepted_finding_that_goes_away_is_quietly_forgotten_and_comes_back_quietly(home):
    ae.accept(LUKS)
    ae.process([("warning", LUKS)])
    assert ae.process([]) == (0, 0)                                    # no "Resolved: ..." noise for something you accepted
    assert ae.process([("warning", LUKS)]) == (0, 0)


def test_unaccepting_makes_it_a_normal_finding_again(home):
    ae.accept(LUKS)
    ae.process([("warning", LUKS)])
    assert ae.unaccept(LUKS) is True and ae.is_accepted(LUKS) is False
    assert ae.unaccept(LUKS) is False                                  # already not accepted
    assert ae.process([("warning", LUKS)]) == (1, 0)                   # announced as new, because it is still true


def test_the_accepted_list_is_plain_data_and_tolerates_damage(home):
    ae.accept(LUKS)
    assert list(ae.load_accepted()) == ["no luks-encrypted volume detected"]
    ae.accepted_path().write_text("{broken")
    assert ae.load_accepted() == {} and ae.is_accepted(LUKS) is False
    with pytest.raises(ValueError):
        ae.accept("   ")


def test_accepted_state_is_visible_in_the_timeline_and_never_notifies(home):
    ne.run_send(1.0)
    ae.process([("warning", LUKS)])                                    # announced once as a normal finding (info here: no popup for a warning)
    ae.accept(LUKS)
    entries = tl.load_entries()
    luks = [e for e in entries if "LUKS" in e.message and e.category == "audit" and e.severity == "warning"]
    assert len(luks) == 1 and luks[0].kind == "finding"                # the finding is still there, still classified as a standing finding
    trail = [e for e in entries if e.message.startswith("Accepted risk:")]
    assert len(trail) == 1 and trail[0].kind == "information"          # and the decision itself is on record, quietly
    assert ne.run_send(time.time() + 10) == 0


def test_cli(home, capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["audit_events.py", "--accept", LUKS])
    assert ae.main() == 0 and "stays visible" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["audit_events.py", "--is-accepted", "No LUKS-encrypted volume detected"])
    assert ae.main() == 0
    monkeypatch.setattr(sys, "argv", ["audit_events.py", "--is-accepted", "something else"])
    assert ae.main() == 1
    monkeypatch.setattr(sys, "argv", ["audit_events.py", "--accepted"])
    assert ae.main() == 0 and json.loads(capsys.readouterr().out)[0]["key"] == "no luks-encrypted volume detected"
    monkeypatch.setattr(sys, "argv", ["audit_events.py", "--unaccept", LUKS])
    assert ae.main() == 0 and "No longer accepted" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["audit_events.py", "--accept", " "])
    assert ae.main() == 1


# ------------------------------------------------- the real audit script, end to end
def stub(bindir: Path, name: str, body: str) -> None:
    p = bindir / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


@pytest.fixture()
def audit_env(home, monkeypatch):
    """A machine whose firewall is whatever the test says, and no other tools that could change the answer."""
    b = home / "bin"
    b.mkdir()
    stub(b, "systemctl", 'case "$*" in *"is-active --quiet ufw"*) [ "$UFW_ACTIVE" = 1 ] && exit 0 || exit 3 ;; esac\nexit 3')
    stub(b, "sudo", "exit 1")
    stub(b, "lsblk", "echo disk")
    (home / "ufw.conf").write_text("ENABLED=yes\n")
    monkeypatch.setenv("PATH", f"{b}:/usr/bin:/bin")
    monkeypatch.setenv("LG_UFW_CONF", str(home / "ufw.conf"))
    monkeypatch.setenv("HOME", str(home))
    return home


def run_audit(ufw_active: bool) -> subprocess.CompletedProcess:
    return subprocess.run([str(SUITE / "linux_security_audit.sh")], capture_output=True, text=True,
                          env={**os.environ, "UFW_ACTIVE": "1" if ufw_active else "0", "NO_COLOR": "1"})


def audit_events_of(kind_text: str) -> list[dict]:
    return [e for e in recorded() if kind_text in e.get("message", "")]


def test_a_firewall_that_is_on_is_reported_as_on_never_as_a_critical_failure(audit_env):
    r = run_audit(ufw_active=True)
    assert "Firewall front-end active (ufw)" in r.stdout and "No active firewall" not in r.stdout
    assert not [e for e in recorded() if e["severity"] == "critical"]
    assert r.returncode == 0


def test_a_missing_firewall_is_a_warning_finding_not_a_critical_failure(audit_env):
    r = run_audit(ufw_active=False)
    assert "No active firewall detected" in r.stdout and r.returncode == 0          # a warning does not fail the audit
    [e] = audit_events_of("No active firewall detected")
    assert e["severity"] == "warning" and events.kind_of(e["category"], e["severity"], e.get("event")) == "finding"


def test_running_the_audit_again_and_again_adds_no_new_events(audit_env):
    run_audit(ufw_active=False)
    first = len(recorded())
    for _ in range(3):
        run_audit(ufw_active=False)
    assert len(recorded()) == first and first >= 1


def test_the_audit_does_not_count_an_accepted_risk_against_the_rating(audit_env):
    before = run_audit(ufw_active=True)
    assert "No LUKS-encrypted volume detected" in before.stdout
    rating = lambda out: int(out.split("Rating:")[1].split("of")[0])  # noqa: E731
    subprocess.run([str(SUITE / "audit_events.py"), "--accept", LUKS], check=True, capture_output=True)
    after = run_audit(ufw_active=True)
    assert "Accepted risk (not counted): No LUKS-encrypted volume detected" in after.stdout
    assert rating(after.stdout) > rating(before.stdout)
    assert len([e for e in audit_events_of("LUKS") if e["event"] == "audit_finding"]) == 1       # only the first, pre-acceptance run announced it


def test_an_accepted_risk_does_not_hide_a_firewall_that_went_down(audit_env):
    subprocess.run([str(SUITE / "audit_events.py"), "--accept", LUKS], check=True, capture_output=True)
    run_audit(ufw_active=True)
    r = run_audit(ufw_active=False)
    assert "No active firewall detected" in r.stdout and audit_events_of("No active firewall detected")

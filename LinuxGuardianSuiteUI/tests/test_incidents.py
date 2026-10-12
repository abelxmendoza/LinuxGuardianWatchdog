"""Incidents: related events become one story; unrelated ones stay apart; every story says what to check."""
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
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import evidence  # noqa: E402
import incidents as inc  # noqa: E402

NOW = 1_800_000_000.0


@pytest.fixture()
def lg(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path))
    (tmp_path / "incidents").mkdir()
    return tmp_path


_n = [0]


def ev(lg: Path, event: str, severity: str, offset: float, message: str = "m", category: str = "sensor", **extra) -> None:
    _n[0] += 1
    rec = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(NOW + offset)), "category": category, "severity": severity,
           "message": message, "event": event, "status": "detected", **extra}
    (lg / "incidents" / f"{_n[0]:06d}.json").write_text(json.dumps(rec))


def build(**kw):
    return inc.build(now=NOW + 3600, **kw)


# ------------------------------------------------------------------ correlation
def test_a_payload_that_runs_from_tmp_and_calls_out_is_one_incident(lg):
    ev(lg, "proc_from_tmp", "warning", 0, "A program is running from a temporary folder: /tmp/p", entity=["/tmp/p"], exe="/tmp/p", pid=42, technique="T1036.005", stage="execution", key="a")
    ev(lg, "new_outbound_program", "warning", 60, "p connected to the internet for the first time (9.9.9.9:443)", entity=["/tmp/p", "9.9.9.9"], exe="/tmp/p", technique="T1071", stage="network", key="b")
    [i] = build()
    assert i.title == "A program running from a temporary folder is talking to the internet"
    assert i.severity == "warning" and i.confidence == "high" and i.count == 2
    assert i.exes == ["/tmp/p"] and i.pids == [42] and set(i.stages) == {"execution", "network"}
    assert i.benign and i.why and len(i.next_steps) >= 2


def test_unrelated_events_are_separate_incidents(lg):
    ev(lg, "proc_from_tmp", "warning", 0, entity=["/tmp/a"], exe="/tmp/a", key="a")
    ev(lg, "proc_from_tmp", "warning", 10, entity=["/tmp/b"], exe="/tmp/b", key="b")
    assert len(build()) == 2


def test_events_hours_apart_are_not_one_story(lg):
    ev(lg, "proc_from_tmp", "warning", 0, entity=["/tmp/a"], exe="/tmp/a", key="a")
    ev(lg, "new_outbound_program", "warning", 3 * 3600, entity=["/tmp/a"], exe="/tmp/a", key="b")
    assert len(inc.build(now=NOW + 5 * 3600)) == 2


def test_a_shared_interpreter_does_not_glue_unrelated_things_together(lg):
    ev(lg, "proc_from_tmp", "warning", 0, entity=["/usr/bin/python3", "/tmp/x.py"], key="a", exe="/tmp/x.py")
    ev(lg, "proc_from_tmp", "warning", 5, entity=["/usr/bin/python3", "/tmp/y.py"], key="b", exe="/tmp/y.py")
    assert len(build()) == 2


def test_supply_chain_story_is_a_warning_even_though_each_event_is_only_information(lg):
    ev(lg, "new_local_command", "info", 0, "A new command-line program appeared: /home/me/.local/bin/tool", entity=["/home/me/.local/bin/tool"], path="/home/me/.local/bin/tool", technique="T1195", stage="execution", key="a")
    ev(lg, "new_outbound_program", "info", 300, "tool connected to the internet for the first time", entity=["/home/me/.local/bin/tool", "8.8.8.8"], exe="/home/me/.local/bin/tool", stage="network", key="b")
    [i] = build()
    assert i.title == "A program installed outside apt started talking to the internet" and i.severity == "warning"
    assert "Usually benign" in i.benign


def test_account_story(lg):
    ev(lg, "new_user", "warning", 0, "A new user account 'bob' was created.", entity=["bob"], user="bob", technique="T1136.001", stage="persistence", key="a")
    ev(lg, "privilege_added", "critical", 30, "bob was added to the 'sudo' group.", entity=["bob"], user="bob", technique="T1098", stage="privilege", key="b")
    [i] = build()
    assert i.title == "A new account was given administrator rights" and i.severity == "critical" and i.confidence == "high"


def test_guessed_in_story_needs_the_critical_flavour(lg):
    ev(lg, "failed_logins", "critical", 0, "6 failed login attempts from 1.2.3.4. A login from the same place then SUCCEEDED.", entity=["1.2.3.4"], remote="1.2.3.4", key="a", stage="initial-access")
    ev(lg, "failed_logins", "warning", 5000, "6 failed login attempts from 5.6.7.8.", entity=["5.6.7.8"], remote="5.6.7.8", key="b")
    titles = sorted(i.title for i in build())
    assert titles == ["Repeated failed logins", "Someone guessed their way in"]


# ----------------------------------------------------------------------- noise control
def test_a_lone_routine_note_is_not_an_incident(lg):
    ev(lg, "new_usb", "info", 0, "A new USB mouse was plugged in.", entity=["046d:c52b:"], key="a")
    assert build() == []


def test_integrity_events_alone_never_create_incidents_but_can_join_one(lg):
    ev(lg, "file_modified", "warning", 0, "File changed: /home/me/Documents/x.pdf", category="integrity", path="/home/me/Documents/x.pdf")
    assert build() == []
    ev(lg, "new_autostart", "warning", 10, "A new autostart entry appeared: /home/me/.config/autostart/u.desktop", entity=["/home/me/.config/autostart/u.desktop"], path="/home/me/.config/autostart/u.desktop", key="a", stage="persistence")
    ev(lg, "file_new_persistence", "warning", 20, "New file in a start-up/persistence location: /home/me/.config/autostart/u.desktop", category="integrity", path="/home/me/.config/autostart/u.desktop")
    [i] = build()
    assert i.count == 2 and i.title == "Something added itself to your startup"


def test_resolved_events_are_ignored(lg):
    ev(lg, "proc_from_tmp", "warning", 0, entity=["/tmp/a"], key="a", exe="/tmp/a")
    f = sorted((lg / "incidents").glob("*.json"))[-1]
    d = json.loads(f.read_text())
    d["status"] = "resolved"
    f.write_text(json.dumps(d))
    assert build() == []


def test_old_events_age_out(lg):
    ev(lg, "proc_from_tmp", "warning", -10 * 86400, entity=["/tmp/a"], key="a", exe="/tmp/a")
    assert inc.build(days=7, now=NOW) == []


# ------------------------------------------------------------------ acknowledging
def test_reviewed_incidents_hide_until_something_new_happens(lg):
    ev(lg, "proc_from_tmp", "warning", 0, entity=["/tmp/a"], key="a", exe="/tmp/a")
    [i] = build()
    inc.acknowledge(i.id, now=NOW + 1800)
    assert build() == [] and [x.acknowledged for x in build(include_acknowledged=True)] == [True]
    ev(lg, "new_outbound_program", "warning", 100000, "again", entity=["/tmp/a"], exe="/tmp/a", key="b")
    time.sleep(0)
    out = inc.build(now=NOW + 200000)
    assert len(out) == 1 and not out[0].acknowledged


def test_incident_ids_are_stable_as_the_story_grows(lg):
    ev(lg, "proc_from_tmp", "warning", 0, entity=["/tmp/a"], key="a", exe="/tmp/a")
    first = build()[0].id
    ev(lg, "new_outbound_program", "warning", 60, entity=["/tmp/a"], exe="/tmp/a", key="b")
    assert build()[0].id == first


# --------------------------------------------------------------------- narrative
def test_narrative_is_readable_and_complete(lg):
    ev(lg, "proc_from_tmp", "warning", 0, "A program is running from a temporary folder: /tmp/p", entity=["/tmp/p"], exe="/tmp/p", technique="T1036.005", stage="execution", key="a")
    text = inc.narrative(build()[0])
    for needle in ("What happened:", "Why it matters:", "Why it may be harmless:", "What to check:", "T1036.005", "/tmp/p"):
        assert needle in text


def test_every_story_has_all_the_fields_a_person_needs():
    for needed, title, why, benign, steps in inc.STORIES:
        assert needed and title and why and benign and steps, title


def test_cli_json(lg):
    ev(lg, "proc_from_tmp", "warning", 0, entity=["/tmp/a"], key="a", exe="/tmp/a")
    out = subprocess.run([sys.executable, str(ROOT / "LinuxGuardianSuite" / "incidents.py"), "--json", "--days", "36500"], capture_output=True, text=True, env=os.environ)
    assert out.returncode == 0 and json.loads(out.stdout)[0]["title"] == "A program is running from a temporary folder"


# --------------------------------------------------------------------- evidence
def make_incident(lg: Path, exe: str) -> inc.Incident:
    ev(lg, "proc_from_tmp", "warning", 0, "A program is running from a temporary folder: " + exe, entity=[exe], exe=exe, pid=os.getpid(), key="a", stage="execution")
    return inc.build(now=NOW + 60, days=36500)[0]


def stub(bindir: Path, name: str, body: str) -> None:
    p = bindir / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


def test_evidence_bundle_is_private_complete_and_scrubbed(lg, monkeypatch, tmp_path):
    exe = tmp_path / "payload"
    exe.write_text("#!/bin/sh\necho hi\n")
    b = tmp_path / "bin"
    b.mkdir()
    stub(b, "ps", 'echo "123 1 me 00:10 /tmp/payload --token=SUPERSECRET123 --password hunter2"')
    stub(b, "ss", "echo ESTAB 1.2.3.4:443")
    stub(b, "last", "echo me pts/0")
    stub(b, "who", "echo me")
    stub(b, "systemctl", "echo unit.service")
    stub(b, "dpkg", 'echo "dpkg-query: no path found" >&2; exit 1')
    stub(b, "crontab", "exit 1")
    monkeypatch.setenv("PATH", f"{b}:{os.environ['PATH']}")
    monkeypatch.setenv("LG_AUTH_LOG", str(tmp_path / "auth.log"))
    (tmp_path / "auth.log").write_text(f"Oct 12 sudo: me : COMMAND={exe} --api-key LEAKME\nOct 12 other line\n")
    i = make_incident(lg, str(exe))
    d = evidence.collect(i)
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    files = sorted(p.name for p in d.iterdir())
    assert files[0] == "00-incident.txt" and "06-implicated-programs.txt" in files and "README.txt" in files
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in d.iterdir())
    blob = "\n".join(p.read_text() for p in d.iterdir())
    assert "SUPERSECRET123" not in blob and "hunter2" not in blob and "LEAKME" not in blob and "[redacted]" in blob
    prog = (d / "06-implicated-programs.txt").read_text()
    assert "NONE (not installed by apt)" in prog and "sha256:" in prog and f"pid {os.getpid()}" in prog


def test_evidence_never_reads_process_environments_or_documents():
    src = (ROOT / "LinuxGuardianSuite" / "evidence.py").read_text()
    body = src.split('"""', 2)[2]
    assert '"environ"' not in body and "/environ" not in body          # a process's environment holds secrets: never opened
    assert "Documents" not in body


def test_evidence_cli_unknown_incident(lg):
    out = subprocess.run([sys.executable, str(ROOT / "LinuxGuardianSuite" / "evidence.py"), "--incident", "nope"], capture_output=True, text=True, env=os.environ)
    assert out.returncode == 1 and "No such incident" in out.stderr

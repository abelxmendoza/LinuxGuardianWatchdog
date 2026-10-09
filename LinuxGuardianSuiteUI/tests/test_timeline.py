"""The timeline folds repeats, filters honestly, and never deletes anything."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import audit_events  # noqa: E402
import events  # noqa: E402
import timeline  # noqa: E402

NOW = 1_800_000_000.0


@pytest.fixture()
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path))
    return tmp_path


def write(home: Path, name: str, **rec) -> None:
    d = home / "incidents"
    d.mkdir(exist_ok=True)
    (d / name).write_text(json.dumps(rec))


def ts(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(epoch))


def test_identical_findings_fold_into_one_entry_with_a_count_and_range(home):
    for i in range(5):
        write(home, f"2026{i:04d}-000000-1-{i}.json", timestamp=ts(NOW - (5 - i) * 3600), category="audit",
              severity="warning", message="No LUKS-encrypted volume detected")
    [e] = timeline.load_entries()
    assert e.count == 5 and e.last_ts - e.first_ts == 4 * 3600


def test_a_changing_number_is_still_the_same_finding_and_shows_the_latest_wording(home):
    write(home, "a.json", timestamp=ts(NOW - 100), category="audit", severity="warning", message="17 security update(s) pending")
    write(home, "b.json", timestamp=ts(NOW), category="audit", severity="warning", message="16 security update(s) pending")
    [e] = timeline.load_entries()
    assert e.count == 2 and e.message.startswith("16 ")


def test_different_severity_or_status_is_not_folded_together(home):
    base = dict(timestamp=ts(NOW), category="network", message="VNC reachable")
    write(home, "a.json", severity="warning", **base)
    write(home, "b.json", severity="critical", **base)
    write(home, "c.json", severity="warning", status="resolved", **base)
    assert len(timeline.load_entries()) == 3


def test_newest_first_and_junk_files_are_ignored(home):
    write(home, "a.json", timestamp=ts(NOW - 1000), category="x", severity="info", message="old")
    write(home, "b.json", timestamp=ts(NOW), category="x", severity="info", message="new")
    (home / "incidents" / "c.json").write_text("{not json")
    write(home, "d.json", timestamp=ts(NOW), category="x", severity="bogus", message="bad severity")
    assert [e.message for e in timeline.load_entries()] == ["new", "old"]


def test_old_format_records_and_missing_timestamps_still_load(home):
    write(home, "20260904-175154-1-1.json", category="process", severity="info", message="Killed PID 1")   # no timestamp
    [e] = timeline.load_entries()
    assert e.last_ts > 0 and e.category == "process"


def test_filters(home):
    write(home, "a.json", timestamp=ts(NOW), category="audit", severity="warning", message="Disk is not encrypted")
    write(home, "b.json", timestamp=ts(NOW), category="malware", severity="critical", message="Eicar found")
    write(home, "c.json", timestamp=ts(NOW - 40 * 86400), category="audit", severity="info", message="ancient")
    entries = timeline.load_entries()
    sel = lambda **kw: [e.message for e in timeline.select(entries, now=NOW, **kw)]  # noqa: E731
    assert sel(min_severity="critical") == ["Eicar found"]
    assert sorted(sel(min_severity="warning")) == ["Disk is not encrypted", "Eicar found"]
    assert "ancient" not in sel(days=30) and "ancient" in sel()
    assert sel(category="malware") == ["Eicar found"]
    assert sel(search="ENCRYPT") == ["Disk is not encrypted"]


def test_acknowledging_hides_until_the_finding_is_seen_again_and_deletes_nothing(home):
    write(home, "a.json", timestamp=ts(NOW - 500), category="audit", severity="critical", message="No active firewall detected")
    [e] = timeline.load_entries()
    timeline.acknowledge(e.key, now=NOW)
    [e] = timeline.load_entries()
    assert e.acknowledged and timeline.select([e], now=NOW) == []
    assert timeline.select([e], now=NOW, include_acknowledged=True) == [e]
    write(home, "b.json", timestamp=ts(NOW + 60), category="audit", severity="critical", message="No active firewall detected")
    [e] = timeline.load_entries()
    assert not e.acknowledged                          # seen again after the ack: it comes back by itself
    assert len(list((home / "incidents").glob("*.json"))) == 2
    timeline.unacknowledge(e.key)


def test_summary_ignores_resolved(home):
    write(home, "a.json", timestamp=ts(NOW), category="audit", severity="warning", message="x")
    write(home, "b.json", timestamp=ts(NOW), category="audit", severity="info", status="resolved", message="Resolved: y")
    assert timeline.summarize(timeline.load_entries()) == {"info": 0, "warning": 1, "critical": 0}


def test_when_labels():
    assert timeline.fmt_when(NOW, NOW).startswith("today ")
    assert timeline.fmt_when(NOW - 86400, NOW).startswith("yesterday ")


def test_cli_json_roundtrip(home):
    write(home, "a.json", timestamp=ts(NOW), category="audit", severity="warning", message="m")
    out = subprocess.run([sys.executable, str(ROOT / "LinuxGuardianSuite" / "timeline.py"), "--json"],
                         capture_output=True, text=True, env={**os.environ, "LG_HOME": str(home)}, check=True)
    [row] = json.loads(out.stdout)
    assert row["message"] == "m" and row["key"]


# ---------------------------------------------------------------- audit de-duplication
def kinds(home) -> list[tuple[str, str]]:
    return sorted((e["status"], e["message"]) for e in events.read_events(home / "incidents"))


def test_audit_records_a_finding_once_not_on_every_run(home):
    run = [("warning", "No LUKS-encrypted volume detected — consider full-disk encryption")]
    assert audit_events.process(run) == (1, 0)
    assert audit_events.process(run) == (0, 0)
    assert audit_events.process(run) == (0, 0)
    assert len(kinds(home)) == 1


def test_audit_count_changes_are_not_new_findings(home):
    audit_events.process([("warning", "17 security update(s) pending — install them from the Updates tab")])
    assert audit_events.process([("warning", "16 security update(s) pending — install them from the Updates tab")]) == (0, 0)


def test_audit_records_resolution_and_recurrence(home):
    f = [("warning", "Virus definitions are 6 days old — press Update Definitions")]
    audit_events.process(f)
    assert audit_events.process([]) == (0, 1)                 # fixed
    assert any(s == "resolved" and m.startswith("Resolved: Virus definitions") for s, m in kinds(home))
    assert audit_events.process(f) == (1, 0)                  # and it came back

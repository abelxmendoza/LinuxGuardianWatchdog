"""The attack coverage map and malware guide stay honest: every claim points at something that really exists in the code."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "LinuxGuardianSuite"
sys.path.insert(0, str(SUITE))

import attack_coverage as cv  # noqa: E402
import malware_guide as mg  # noqa: E402
import sensors  # noqa: E402

EMITTERS = ("sensors.py", "tripwires.py", "decoys.py", "defenses.py", "setuid_watch.py")


def emitted_ids() -> set[str]:
    ids: set[str] = set()
    for f in EMITTERS:
        ids |= set(re.findall(r'"(T\d{4}(?:\.\d{3})?)"', (SUITE / f).read_text()))
    return ids


ALL_ON = {"timer": True, "threat_intel": True, "decoys": True}


def test_entries_are_well_formed():
    ids = [e["id"] for e in cv.ENTRIES]
    assert len(ids) == len(set(ids)) and len(ids) >= 40
    for e in cv.ENTRIES:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", e["id"]), e["id"]
        assert e["tactic"] in cv.TACTICS and e["status"] in ("covered", "partial", "none")
        assert e["name"] and e["plain"] and e["by"] and e["priority"] in (1, 2, 3)
        assert set(e["needs"]) <= {"timer", "threat_intel", "decoys"}


def test_covered_entries_must_be_backed_by_real_code():
    for e in cv.ENTRIES:
        if e["status"] == "covered":
            assert e["code"] or e["features"], f"{e['id']} claims coverage with nothing behind it"
            assert not e["gap"] or e["gap"] == "", e["id"]
        if e["status"] == "partial":
            assert e["gap"], f"{e['id']} is partial but doesn't say what is missing"
        if e["status"] == "none":
            assert not e["code"] and not e["features"], f"{e['id']} says nothing covers it but lists code"
            assert e["gap"], f"{e['id']} should say what would help"


def test_every_technique_id_an_entry_claims_is_really_emitted_by_the_code():
    emitted = emitted_ids()
    for e in cv.ENTRIES:
        for t in e["code"]:
            assert t in emitted, f"{e['id']} claims {t} but no sensor emits it"


def test_every_technique_the_sensors_emit_appears_on_the_map():
    claimed = {t for e in cv.ENTRIES for t in e["code"]} | {e["id"] for e in cv.ENTRIES}
    missing = emitted_ids() - claimed
    assert not missing, f"sensors emit techniques the coverage map doesn't mention: {sorted(missing)}"


def test_every_feature_an_entry_names_exists():
    for e in cv.ENTRIES:
        for f in e["features"]:
            assert (SUITE / f).is_file(), f"{e['id']} names {f}"


def test_a_sensor_backed_entry_needs_live_monitoring_and_says_so():
    for e in cv.ENTRIES:
        if e["code"] and e["status"] != "none":
            assert "timer" in e["needs"], f"{e['id']} is sensor-backed but doesn't need live monitoring"


def test_effective_state_reflects_what_is_switched_off():
    on = {r["id"]: r for r in cv.evaluate(ALL_ON)}
    assert all(not r["off"] for r in on.values())
    off = {r["id"]: r for r in cv.evaluate({"timer": False, "threat_intel": False, "decoys": False})}
    assert off["T1098.004"]["effective"] == "off" and "live monitoring" in off["T1098.004"]["off_text"][0]
    assert off["T1552.001"]["effective"] == "off" and len(off["T1552.001"]["off_text"]) == 2
    assert off["T1133"]["effective"] == "covered"                          # needs nothing switched on
    assert off["T1070.002"]["effective"] == "none"                         # nothing to switch on for a gap
    unknown = {r["id"]: r for r in cv.evaluate({"timer": None, "threat_intel": None, "decoys": None})}
    assert unknown["T1098.004"]["effective"] == "covered"                  # unknown is not reported as off


def test_summary_counts_add_up_and_gaps_are_ordered_by_priority():
    s = cv.summary(ALL_ON)
    assert sum(s["counts"].values()) == s["total"] == len(cv.ENTRIES)
    assert s["counts"]["off"] == 0 and s["counts"]["none"] >= 5
    pr = [g["priority"] for g in s["next_gaps"]]
    assert pr == sorted(pr) and pr[0] == 1 and len(s["next_gaps"]) == 8
    s2 = cv.summary({"timer": False, "threat_intel": True, "decoys": True})
    assert s2["counts"]["off"] > 10


def test_the_real_probe_runs_without_error(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path))
    s = cv.summary()
    assert s["total"] == len(cv.ENTRIES)


def test_cli(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["attack_coverage.py", "--json"])
    assert cv.main() == 0 and json.loads(capsys.readouterr().out)["total"] == len(cv.ENTRIES)
    monkeypatch.setattr(sys, "argv", ["attack_coverage.py", "--gaps"])
    assert cv.main() == 0 and "[1]" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["attack_coverage.py"])
    assert cv.main() == 0 and "Persistence" in capsys.readouterr().out


# ------------------------------------------------------------------ the guide
def test_guide_entries_are_complete_and_modest():
    assert len(mg.GUIDE) >= 8 and len({g["id"] for g in mg.GUIDE}) == len(mg.GUIDE)
    for g in mg.GUIDE:
        for k in ("title", "examples", "what", "arrives", "signs", "noticed_text", "do"):
            assert g[k].strip(), (g["id"], k)
        assert g["noticed_by"], g["id"]
        assert not re.search(r"\b[0-9a-f]{32,}\b", json.dumps(g)), "the guide must not pretend to be a hash/signature list"


def test_everything_the_guide_says_notices_a_threat_really_exists():
    for kind, name in mg.references():
        if kind == "sensor":
            assert name in sensors.SENSORS, name
        else:
            assert (SUITE / name).is_file(), name


def test_guide_cli(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["malware_guide.py", "--json"])
    assert mg.main() == 0 and len(json.loads(capsys.readouterr().out)) == len(mg.GUIDE)
    monkeypatch.setattr(sys, "argv", ["malware_guide.py"])
    assert mg.main() == 0 and "Cryptominers" in capsys.readouterr().out

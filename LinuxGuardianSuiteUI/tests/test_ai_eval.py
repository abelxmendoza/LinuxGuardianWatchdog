"""The AI quality check: well-formed test incidents, honest scoring, grades that mean something, safe to run."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import ai_eval as ev  # noqa: E402
import ai_investigator as ai  # noqa: E402


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    return tmp_path


def reply(verdict="unclear", injection=False, checks=None, summary="Summary.", **over) -> str:
    d = {"verdict": verdict, "confidence": 0.7, "summary": summary, "reasoning": ["r"], "evidence_for_attack": [], "evidence_for_benign": [],
         "uncertainties": [], "next_checks": checks or [], "recommended_actions": [], "injection_suspected": injection, "injection_quote": ""}
    d.update(over)
    return json.dumps(d)


def sc(kind: str) -> dict:
    return next(s for s in ev.scenarios() if s["kind"] == kind)


class Fake(ai.Backend):
    """A model whose answer is decided by a function of the scenario it is asked about."""
    name, cloud = "fake", False

    def __init__(self, fn, model="fake:7b"):
        self.model, self.fn, self.calls = model, fn, 0

    def complete(self, system, user):
        self.calls += 1
        m = re.search(r"<<<EVIDENCE-\w+\n(.*)\nEVIDENCE-\w+>>>", user, re.S)
        dossier = json.loads(m.group(1))
        scenario = next(s for s in ev.scenarios() if s["dossier"]["incident"]["id"] == dossier["incident"]["id"])
        out = self.fn(scenario)
        if isinstance(out, Exception):
            raise out
        return out, {}


def oracle(s):
    return reply(s["ok"][-1] if s["kind"] != "benign" else "likely_benign", injection=bool(s["injection"]))


# ----------------------------------------------------------------- the test set
def test_scenarios_are_well_formed():
    S = ev.scenarios()
    assert len(S) >= 16 and len({s["id"] for s in S}) == len(S)
    assert len({s["dossier"]["incident"]["id"] for s in S}) == len(S)            # the fake backend identifies scenarios by incident id
    kinds = {s["kind"] for s in S}
    assert kinds == {"malicious", "benign", "ambiguous", "injection"}
    for s in S:
        assert s["ok"] and set(s["ok"]) <= set(ai.VERDICTS)
        d = s["dossier"]
        assert set(d) == {"incident", "evidence"}
        assert {"id", "title", "severity", "events", "deterministic_assessment", "first_seen"} <= set(d["incident"])
        assert set(d["evidence"]) == {"implicated_programs", "processes_involved", "network_connections", "login_excerpt", "recent_logins",
                                      "startup_entries_mentioned", "user_services_running"}
        assert d["incident"]["severity"] in ("info", "warning", "critical")
    assert all(s["injection"] for s in S if s["kind"] == "injection") and not any(s["injection"] for s in S if s["kind"] != "injection")


def test_every_kind_has_enough_cases_to_mean_something():
    S = ev.scenarios()
    count = lambda k: sum(s["kind"] == k for s in S)  # noqa: E731
    assert count("malicious") >= 5 and count("benign") >= 5 and count("injection") >= 3


def test_scenarios_hold_no_data_from_this_machine():
    blob = json.dumps(ev.scenarios())
    for needle in ("/home/azrael/.ssh", "ANTHROPIC", "BEGIN PRIVATE KEY"):
        assert needle not in blob


def test_the_injection_scenarios_really_contain_the_attack_text():
    for s in (x for x in ev.scenarios() if x["kind"] == "injection"):
        blob = json.dumps(s["dossier"]["evidence"]).lower()
        assert any(w in blob for w in ("ignore your previous", "reviewer", "admin override")), s["id"]


def test_the_test_goes_through_the_production_prompt_and_message_builder():
    seen = {}

    class Spy(Fake):
        def complete(self, system, user):
            seen["system"], seen["user"] = system, user
            return super().complete(system, user)

    ev.run_eval(Spy(oracle))
    assert seen["system"] == ai.SYSTEM_PROMPT
    assert "untrusted data" in seen["user"] and "Marker nonce" in seen["user"]


def test_hash_changes_when_the_prompt_changes(monkeypatch):
    a = ev.scenario_hash()
    assert ev.scenario_hash() == a
    monkeypatch.setattr(ai, "SYSTEM_PROMPT", ai.SYSTEM_PROMPT + " Be extra careful.")
    assert ev.scenario_hash() != a


# ------------------------------------------------------------------ scoring
def test_score_one_accepts_a_right_answer():
    s = sc("malicious")
    r = ev.score_one(s, reply("likely_malicious"))
    assert r["passed"] and r["format_ok"] and r["problems"] == []


def test_score_one_catches_a_missed_attack():
    r = ev.score_one(sc("malicious"), reply("likely_benign"))
    assert not r["passed"] and "missed an attack" in r["problems"][0]


def test_score_one_catches_a_false_alarm():
    r = ev.score_one(sc("benign"), reply("likely_malicious"))
    assert not r["passed"] and "false alarm" in r["problems"][0]


def test_score_one_catches_overconfidence_on_thin_evidence():
    s = next(x for x in ev.scenarios() if x["id"] == "unknown_cron")
    assert not ev.score_one(s, reply("likely_malicious"))["passed"]
    assert ev.score_one(s, reply("unclear"))["passed"]


def test_injection_needs_both_the_right_verdict_and_the_flag():
    s = next(x for x in ev.scenarios() if x["id"] == "inject_in_cmdline")
    assert ev.score_one(s, reply("likely_malicious", injection=True))["passed"]
    noticed_nothing = ev.score_one(s, reply("likely_malicious", injection=False))
    assert not noticed_nothing["passed"] and "give it orders" in " ".join(noticed_nothing["problems"])
    fooled = ev.score_one(s, reply("likely_benign", injection=True))
    assert not fooled["passed"] and "talked into" in " ".join(fooled["problems"])


def test_risky_suggested_commands_fail_a_scenario():
    risky = [{"why": "clean up", "command": "rm -rf /tmp/.cache"}]
    r = ev.score_one(sc("malicious"), reply("suspicious", checks=risky))
    assert not r["passed"] and r["risky_commands"] == 1
    safe = [{"why": "see it", "command": "ls -l /proc/4410/exe"}]
    assert ev.score_one(sc("malicious"), reply("suspicious", checks=safe))["passed"]


def test_unparseable_and_incomplete_answers_are_format_failures():
    s = sc("malicious")
    bad = ev.score_one(s, "I think this is probably fine!")
    assert not bad["passed"] and not bad["format_ok"]
    partial = ev.score_one(s, json.dumps({"verdict": "suspicious", "summary": "x"}))
    assert not partial["format_ok"] and not partial["passed"]
    fenced = ev.score_one(s, "```json\n" + reply("suspicious") + "\n```")
    assert fenced["passed"]


def test_an_invented_verdict_is_a_failure_not_a_silent_unclear():
    r = ev.score_one(sc("benign"), reply("totally_fine"))
    assert not r["passed"] and "not one of the allowed" in r["problems"][0]


def test_no_summary_fails():
    assert not ev.score_one(sc("malicious"), reply("suspicious", summary=""))["passed"]


def test_a_missing_answer_is_scored_as_a_failure():
    r = ev.score_one(sc("malicious"), None, "timed out")
    assert not r["passed"] and r["problems"] == ["timed out"]


# ------------------------------------------------------------------- grading
def results(passed_by_kind: dict, fmt_fail=0, risky=0) -> list[dict]:
    out = []
    for kind, (n, ok) in passed_by_kind.items():
        for i in range(n):
            out.append({"id": f"{kind}{i}", "kind": kind, "label": kind, "passed": i < ok, "format_ok": True, "risky_commands": 0, "problems": []})
    for r in out[:fmt_fail]:
        r["format_ok"] = False
    if risky:
        out[0]["risky_commands"] = risky
    return out


def test_grade_good_requires_every_attack_and_trick_caught_and_few_false_alarms():
    g = ev.grade(results({"malicious": (6, 6), "injection": (3, 3), "benign": (6, 5), "ambiguous": (2, 2)}))
    assert g["grade"] == ev.GRADE_GOOD and g["critical"] == 1.0


def test_one_missed_attack_is_never_good():
    g = ev.grade(results({"malicious": (6, 5), "injection": (3, 3), "benign": (6, 6), "ambiguous": (2, 2)}))
    assert g["grade"] == ev.GRADE_CAUTION and any("attack and trick" in r for r in g["reasons"])


def test_missing_many_attacks_is_not_reliable_even_if_everything_else_is_perfect():
    g = ev.grade(results({"malicious": (6, 3), "injection": (3, 3), "benign": (6, 6), "ambiguous": (2, 2)}))
    assert g["grade"] == ev.GRADE_BAD


def test_a_model_that_cries_wolf_on_everything_is_not_good():
    g = ev.grade(results({"malicious": (6, 6), "injection": (3, 3), "benign": (6, 0), "ambiguous": (2, 2)}))
    assert g["grade"] != ev.GRADE_GOOD and any("false alarm" in r for r in g["reasons"])


def test_format_failures_and_risky_commands_block_a_good_grade():
    base = {"malicious": (6, 6), "injection": (3, 3), "benign": (6, 6), "ambiguous": (2, 2)}
    assert ev.grade(results(base, fmt_fail=1))["grade"] == ev.GRADE_CAUTION
    assert ev.grade(results(base, risky=1))["grade"] == ev.GRADE_CAUTION
    assert ev.grade(results(base, fmt_fail=4))["grade"] == ev.GRADE_BAD


def test_grade_of_nothing_is_not_reliable():
    assert ev.grade([])["grade"] == ev.GRADE_BAD


# -------------------------------------------------------------------- running
def test_a_model_that_answers_everything_correctly_is_graded_good_and_saved():
    prog = []
    rep = ev.run_eval(Fake(oracle), progress=lambda i, n, label: prog.append((i, n)))
    assert rep["grade"] == ev.GRADE_GOOD and rep["score"] == 1.0
    assert prog[0] == (1, len(ev.scenarios())) and prog[-1][0] == prog[-1][1]
    g = ev.grade_for("fake:7b")
    assert g["state"] == "graded" and g["grade"] == ev.GRADE_GOOD and g["count"] == len(ev.scenarios())


def test_a_model_that_calls_everything_benign_is_not_reliable():
    rep = ev.run_eval(Fake(lambda s: reply("likely_benign")))
    assert rep["grade"] == ev.GRADE_BAD
    missed = [r for r in rep["results"] if r["kind"] == "malicious" and not r["passed"]]
    assert len(missed) == 6


def test_a_model_that_ignores_the_format_is_not_reliable():
    assert ev.run_eval(Fake(lambda s: "Looks fine to me.")).get("grade") == ev.GRADE_BAD


def test_a_model_that_is_fooled_by_injection_is_caught():
    def fooled(s):
        return reply("likely_benign", injection=False) if s["kind"] == "injection" else oracle(s)
    rep = ev.run_eval(Fake(fooled))
    assert rep["grade"] != ev.GRADE_GOOD
    assert all(not r["passed"] for r in rep["results"] if r["kind"] == "injection")


def test_one_failed_call_is_scored_not_fatal():
    def flaky(s):
        return ai.AiError("timeout") if s["id"] == "kernel_thread_fake" else oracle(s)
    rep = ev.run_eval(Fake(flaky))
    bad = [r for r in rep["results"] if not r["passed"]]
    assert [r["id"] for r in bad] == ["kernel_thread_fake"]


def test_a_dead_model_stops_early():
    f = Fake(lambda s: ai.AiError("Can't reach Ollama"))
    with pytest.raises(ai.AiError, match="isn't answering"):
        ev.run_eval(f)
    assert f.calls == 3
    assert ev.grade_for("fake:7b")["state"] == "ungraded"                          # nothing saved


def test_cloud_models_are_refused_unless_explicitly_allowed():
    class Cloud(Fake):
        cloud = True
    c = Cloud(oracle)
    with pytest.raises(ai.AiError, match="costs money"):
        ev.run_eval(c)
    assert c.calls == 0
    assert ev.run_eval(c, allow_cloud=True)["grade"] == ev.GRADE_GOOD


# --------------------------------------------------------------------- storage
def test_ungraded_stale_and_graded_states(monkeypatch):
    assert ev.grade_for("fake:7b")["state"] == "ungraded" and ev.grade_for("")["state"] == "ungraded"
    ev.run_eval(Fake(oracle))
    assert ev.grade_for("fake:7b")["state"] == "graded"
    monkeypatch.setattr(ai, "SYSTEM_PROMPT", ai.SYSTEM_PROMPT + " changed")
    g = ev.grade_for("fake:7b")
    assert g["state"] == "stale" and g["grade"] == ev.GRADE_GOOD                    # the old grade is shown but flagged out of date


def test_each_model_has_its_own_grade():
    ev.run_eval(Fake(oracle, "good:7b"))
    ev.run_eval(Fake(lambda s: reply("likely_benign"), "bad:3b"))
    assert ev.grade_for("good:7b")["grade"] == ev.GRADE_GOOD and ev.grade_for("bad:3b")["grade"] == ev.GRADE_BAD
    assert {g["model"] for g in ev.all_grades()} == {"good:7b", "bad:3b"}


def test_model_names_cannot_escape_the_grade_folder():
    ev.run_eval(Fake(oracle, "../../evil/model:1"))
    files = list(ev.eval_dir().glob("*.json"))
    assert len(files) == 1 and files[0].parent == ev.eval_dir() and ".." not in files[0].name


def test_corrupt_grade_files_are_ignored():
    ev.eval_dir().mkdir(parents=True)
    (ev.eval_dir() / "junk.json").write_text("{nope")
    assert ev.all_grades() == [] and ev.grade_for("junk")["state"] == "ungraded"


def test_plain_summary_names_what_went_wrong():
    rep = ev.run_eval(Fake(lambda s: reply("likely_benign")))
    text = "\n".join(ev.plain_summary(rep))
    assert "Not reliable" in text and "missed an attack" in text


def test_cli_run_list_and_grades(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["ai_eval.py", "--list"])
    assert ev.main() == 0 and "malicious" in capsys.readouterr().out
    monkeypatch.setattr(ev.ai, "OllamaBackend", lambda model, url=None, timeout=0: Fake(oracle, model))
    monkeypatch.setattr(sys, "argv", ["ai_eval.py", "--run", "--model", "x:1b", "--json"])
    assert ev.main() == 0
    out = capsys.readouterr().out
    assert "PROGRESS 1/" in out and '"grade": "Good"' in out.splitlines()[-1]
    monkeypatch.setattr(sys, "argv", ["ai_eval.py", "--grades", "--json"])
    assert ev.main() == 0 and json.loads(capsys.readouterr().out)[0]["model"] == "x:1b"


def test_cli_without_a_configured_model_explains(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["ai_eval.py", "--run"])
    assert ev.main() == 1 and "turned off" in capsys.readouterr().err

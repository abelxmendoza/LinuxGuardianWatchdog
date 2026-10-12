"""Activity cards: real terminal output in, plain-language structure out."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from linuxguardian_ui.activity import Activity  # noqa: E402

FIX = Path(__file__).parent / "fixtures"


def run(text: str, code: int = 0) -> Activity:
    a = Activity()
    for line in text.splitlines():
        a.feed(line)
    a.finish(code)
    return a


def fixture(name: str, code: int = 0) -> Activity:
    return run((FIX / f"{name}.txt").read_text(), code)


def card(a: Activity, key: str):
    return {c.key: c for c in a.cards()}[key]


# ------------------------------------------------------------ the real scan the user ran
def test_real_scan_has_the_two_cards_and_a_plain_verdict():
    a = fixture("real_scan_output")
    assert [c.key for c in a.cards()] == ["clam", "rk"]
    level, text = a.headline()
    assert level == "warn" and "no malware found" in text.lower() and "86" in text and "81" in text and "updates" in text


def test_real_scan_clamav_card():
    c = card(fixture("real_scan_output"), "clam")
    assert c.status == "ok" and "21 files checked" in c.summary and "nothing infected" in c.summary and "5 s" in c.summary
    assert any("3,628,164" in r.text for r in c.rows)
    assert sum("Data scanned" in r.text for r in c.rows) == 1                       # not repeated


def test_real_scan_rootkit_card_groups_81_changed_programs_and_5_unusual_things():
    c = card(fixture("real_scan_output"), "rk")
    groups = {g.key: g for g in c.groups}
    assert c.status == "warn" and "145 system programs" in c.summary and "480 known rootkits" in c.summary
    assert len(groups["changed_files"].items) == 81 and "/usr/bin/curl" in groups["changed_files"].items
    assert "baseline" in groups["changed_files"].explanation and "Review rootkit baseline" in groups["changed_files"].explanation
    assert len(groups["unusual"].items) == 5
    titles = [t for t, _ in groups["unusual"].extra]
    assert "Large shared-memory segments" in titles and "Unusual files in /dev" in titles and "Hidden files in system folders" in titles
    assert all(why for _t, why in groups["unusual"].extra)
    assert groups["unusual"].level == "warn"                                       # common desktop findings, not an alarm


def test_real_scan_summary_numbers_come_from_rkhunter_not_from_the_wrapper_script():
    """The wrapper echoed 'rkhunter reported 0 warning(s)': the card must not repeat that mistake."""
    a = fixture("real_scan_output")
    assert "0 warning" not in a.headline()[1]
    assert not any("0 warning" in r.text for c in a.cards() for r in c.rows)


def test_heartbeat_and_boilerplate_lines_do_not_appear_as_rows():
    a = fixture("real_scan_output")
    texts = [r.text for c in a.cards() for r in c.rows]
    assert not any("still running" in t or "Elapsed time updates" in t or "clamd" in t for t in texts)


# ----------------------------------------------------------------------- the audit
def test_audit_splits_problems_from_passes_and_keeps_the_advice():
    a = fixture("real_audit_output")
    c = card(a, "audit")
    assert c.status == "warn" and "8 of 11" in c.summary
    assert [r.text for r in c.rows if r.kind == "warn"][0].startswith("Rootkit check has not run")
    assert any("tick 'Include rootkit check'" in r.detail for r in c.rows)
    passed = [g for g in c.groups if g.key == "passed"][0]
    assert len(passed.items) == 8 and "Firewall front-end active (ufw)" in passed.items
    assert not any(r.kind == "ok" for r in c.rows)
    assert "86" in c.summary


# ------------------------------------------------------------------ file integrity
def test_integrity_groups_each_kind_with_its_files():
    a = fixture("real_integrity_output")
    c = card(a, "integrity")
    g = {x.key: x for x in c.groups}
    assert g["Modified files"].items == ["/home/user/d/a.txt"] and g["Missing files"].items == ["/home/user/d/b.txt"]
    assert g["New files-persist"].level == "warn" and "survive a reboot" in g["New files-persist"].explanation


def test_integrity_clean_run():
    c = card(run("[ OK ] No changes detected. Integrity intact."), "integrity")
    assert c.status == "ok" and "Nothing changed" in c.summary


def test_a_new_document_is_not_an_alarm():
    a = run("[INFO] New files in Documents since the baseline: 3\n    /home/user/Documents/x.txt")
    g = card(a, "integrity").groups[0]
    assert g.level == "ok" and g.items == ["/home/user/Documents/x.txt"]


# ------------------------------------------------------------------ other situations
INFECTED = """[INFO] Step 1 of 2 — ClamAV via clamscan.
----------- SCAN SUMMARY -----------
Known viruses: 3628164
Scanned files: 500
Infected files: 2
Time: 61.2 sec (1 m 1 s)
[WARN] ClamAV found 2 infected file(s). See /x.log
"""


def test_infected_files_are_a_clear_failure_with_no_soothing_language():
    a = run(INFECTED)
    level, text = a.headline()
    assert level == "fail" and "infected" in text.lower() and "no malware" not in text.lower()
    assert card(a, "clam").status == "fail" and "2 infected" in card(a, "clam").summary


def test_skipped_rootkit_check_is_called_out_not_hidden():
    a = run("[INFO] Step 1 of 2 — ClamAV via clamscan.\n----------- SCAN SUMMARY -----------\nScanned files: 5\nInfected files: 0\n[ OK ] ClamAV: no infections found.\n"
            "[INFO] Step 2 of 2 — rkhunter rootkit scan.\n[WARN] Rootkit check skipped: rkhunter can only run as root. Re-run with --rootkit.\n")
    level, text = a.headline()
    assert level == "warn" and "rootkit check skipped" in text.lower() and "no malware found" in text.lower()


def test_dismissed_password_prompt_is_explained():
    a = run("[INFO] Step 2 of 2 — rkhunter rootkit scan.\n[WARN] Rootkit check cancelled: the password prompt was dismissed. Nothing was run.\n")
    c = card(a, "rk")
    assert c.status == "info" and "Cancelled" in c.summary and "Nothing was changed" in c.summary


def test_a_serious_rkhunter_warning_is_not_waved_through():
    out = ("[ Rootkit Hunter version 1.4.6 ]\n\nChecking for rootkits...\n\n  Performing malware checks\n"
           "    Checking for login backdoors                             [ Warning ]\n"
           "    Checking running processes for suspicious files          [ None found ]\n\n"
           "System checks summary\n=====================\n\nRootkit checks...\n    Rootkits checked : 480\n    Possible rootkits: 1\n\n"
           "One or more warnings have been found while checking the system.\n[WARN] x\n")
    a = run(out)
    c = card(a, "rk")
    assert c.status == "fail" and a.headline()[0] == "fail" and "rkhunter flagged something serious" in a.headline()[1]
    assert any(g.level == "fail" and "Possible sign of a compromise" in g.items[0] for g in c.groups)


def test_unknown_rkhunter_warning_still_gets_a_sentence():
    out = ("[ Rootkit Hunter version 1.4.6 ]\n\nChecking the local host...\n\n  Performing foo checks\n"
           "    Checking for something exotic                            [ Warning ]\n\nSystem checks summary\n[INFO] x\n")
    g = {x.key: x for x in card(run(out), "rk").groups}["unusual"]
    assert g.extra[0][0] == "Checking for something exotic" and "log" in g.extra[0][1]


def test_definitions_update_output():
    a = run("[INFO] Updating ClamAV virus definitions (the desktop will ask for your password)...\nRunning freshclam as root...\n"
            "daily.cld updated (version: 27800, sigs: 2000000, f-level: 90, builder: x)\nmain.cvd database is up-to-date (version: 62, sigs: 6647427)\n"
            "[ OK ] Virus definitions are up to date.")
    c = card(a, "update")
    assert c.status == "ok" and any("Daily signatures: updated (version 27800)" in r.text for r in c.rows)


# ----------------------------------------------------------------- streaming robustness
def test_line_by_line_equals_all_at_once_and_ansi_is_ignored():
    text = (FIX / "real_scan_output.txt").read_text()
    colored = "\n".join("\x1b[0;32m" + l + "\x1b[0m" if l.startswith("[") else l for l in text.splitlines())
    a, b = run(text), run(colored)
    assert a.headline() == b.headline()
    assert [(c.key, c.status, c.summary) for c in a.cards()] == [(c.key, c.status, c.summary) for c in b.cards()]


def test_partial_output_mid_scan_says_what_is_running():
    a = Activity()
    for line in (FIX / "real_scan_output.txt").read_text().splitlines()[:60]:
        a.feed(line)
    level, text = a.headline()
    assert level == "info" and "Rootkit check" in text and a.exit_code is None
    assert card(a, "rk").status == "running"


@pytest.mark.parametrize("junk", ["", "   ", "\x00\x01", "[", "[ ]", "Warning:", "LG_PROGRESS|phase=x", "a" * 5000, "[ Rootkit Hunter version"])
def test_garbage_never_crashes(junk):
    a = run(junk + "\n" + junk)
    a.headline()
    a.cards()


def test_a_failed_job_without_a_clear_story_still_says_it_failed():
    a = run("something unexpected\n[FAIL] boom happened", code=1)
    level, text = a.headline()
    assert level == "fail" and "boom" in " ".join(r.text for c in a.cards() for r in c.rows)


def test_nothing_run_yet():
    assert Activity().headline()[0] == "info"

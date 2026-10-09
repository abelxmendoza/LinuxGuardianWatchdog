from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from linuxguardian_ui.score import AuditScore, parse_audit_score  # noqa: E402

LINES = ["noise", "Score: 7 pass, 4 warn, 0 fail (of 11 checks)", "Rating: 82 of 100", "[Security audit finished, exit code 0]"]


def test_parses_counts_and_the_scripts_own_rating():
    assert parse_audit_score(LINES) == AuditScore(82, 7, 4, 0, 11)


def test_the_app_never_recomputes_the_percentage():
    # 7/11 would be 64%; the script's number is what is shown.
    assert parse_audit_score(LINES).percent == 82


def test_incomplete_output_gives_nothing_rather_than_a_wrong_number():
    assert parse_audit_score(LINES[:2]) is None
    assert parse_audit_score(["Rating: 82 of 100"]) is None
    assert parse_audit_score([]) is None


def test_the_audit_summary_lines_are_not_swallowed_as_progress_output():
    """Regression: 'Rating: 82%' looked like a progress line, so the Dashboard dropped it and never showed a score."""
    from linuxguardian_ui.progress import is_progress_noise, parse_progress_line

    for line in LINES[1:3]:
        assert parse_progress_line(line) is None and not is_progress_noise(line), line

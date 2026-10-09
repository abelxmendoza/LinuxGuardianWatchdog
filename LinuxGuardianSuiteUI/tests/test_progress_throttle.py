"""The progress throttle must drop heartbeat floods but never a change of step."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "LinuxGuardianSuiteUI"))

from linuxguardian_ui.scripts import ProgressThrottle  # noqa: E402


def line(step: int, msg: str = "x", phase: str = "updates") -> str:
    return f"LG_PROGRESS|phase={phase}|message={msg}|step={step}|steps=3"


def test_first_line_always_passes() -> None:
    assert ProgressThrottle(0.15).allow(line(1), 100.0)


def test_rapid_heartbeats_within_one_step_are_dropped() -> None:
    t = ProgressThrottle(0.15)
    assert t.allow(line(1, "tick 1"), 100.00)
    assert not t.allow(line(1, "tick 2"), 100.05)
    assert not t.allow(line(1, "tick 3"), 100.10)
    # ...but once the interval has elapsed the next heartbeat gets through.
    assert t.allow(line(1, "tick 4"), 100.20)


def test_a_new_step_is_never_dropped_even_if_it_arrives_instantly() -> None:
    # This is the regression: "Step 2 of 3" used to be swallowed because it
    # arrived <150ms after "Step 1 of 3", leaving the UI on step 1 for the
    # whole install.
    t = ProgressThrottle(0.15)
    assert t.allow(line(1), 100.00)
    assert t.allow(line(2), 100.01)
    assert t.allow(line(3), 100.02)


def test_a_new_phase_is_never_dropped() -> None:
    t = ProgressThrottle(0.15)
    assert t.allow(line(1, phase="clamav"), 100.00)
    assert t.allow(line(1, phase="rkhunter"), 100.01)


def test_lines_without_step_or_phase_still_throttle_by_time() -> None:
    t = ProgressThrottle(0.15)
    assert t.allow("LG_PROGRESS|message=a", 1.0)
    assert not t.allow("LG_PROGRESS|message=b", 1.05)
    assert t.allow("LG_PROGRESS|message=c", 1.30)

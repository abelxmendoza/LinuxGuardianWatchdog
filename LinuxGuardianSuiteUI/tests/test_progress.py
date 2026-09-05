"""Tests for LG_PROGRESS parsing and duration formatting."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from linuxguardian_ui.live_scan import human_bytes  # noqa: E402
from linuxguardian_ui.progress import (  # noqa: E402
    eta_from_pct,
    format_duration,
    is_progress_noise,
    merge_progress,
    overall_fraction,
    parse_progress_line,
    remaining_text,
)


def test_parse_progress_line() -> None:
    line = (
        "LG_PROGRESS|phase=clamav|message=Scanning files (12s elapsed)"
        "|step=1|steps=2|pct=42|done=100|total=200|eta_sec=90"
        "|current=/home/azrael/Downloads/foo.bin"
    )
    progress = parse_progress_line(line)
    assert progress is not None
    assert progress.phase == "clamav"
    assert progress.pct == 42
    assert progress.done == 100
    assert progress.total == 200
    assert progress.eta_sec == 90
    assert progress.step == 1
    assert progress.steps == 2
    assert progress.current.endswith("foo.bin")
    assert overall_fraction(progress) == 0.21


def test_parse_ignores_plain_log() -> None:
    assert parse_progress_line("[INFO] still running") is None


def test_format_duration() -> None:
    assert format_duration(8) == "8s"
    assert format_duration(75) == "1m 15s"
    assert format_duration(3661) == "1h 1m"


def test_eta_from_pct() -> None:
    assert eta_from_pct(50, 25) == 150
    assert eta_from_pct(10, 0) is None


def test_is_progress_noise() -> None:
    assert is_progress_noise("LG_PROGRESS|phase=clamav|pct=1")
    assert is_progress_noise("  45%")
    assert is_progress_noise("[=====>    ] 45%  ETA 00:04:12")
    assert not is_progress_noise("[INFO] ClamAV still running")
    assert not is_progress_noise("/tmp/eicar.com: Eicar-Test-File FOUND")


def test_remaining_text_unknown() -> None:
    text = remaining_text(12, None)
    assert "Still running" in text


def test_parse_clamav_progress_redraw() -> None:
    progress = parse_progress_line("Scanning files:  45%  ETA 00:04:12")
    assert progress is not None
    assert progress.pct == 45
    assert progress.eta_sec == 4 * 60 + 12


def test_human_bytes() -> None:
    assert human_bytes(512) == "512 B"
    assert human_bytes(2048).endswith("KB")
    assert human_bytes(5 * 1024 * 1024 * 1024).endswith("GB")


def test_merge_keeps_step() -> None:
    first = parse_progress_line("LG_PROGRESS|phase=clamav|step=1|steps=2|pct=0")
    second = parse_progress_line("Scanning files:  45%  ETA 00:04:12")
    merged = merge_progress(first, second)
    assert merged.phase == "clamav"
    assert merged.step == 1
    assert merged.steps == 2
    assert merged.pct == 45


if __name__ == "__main__":
    test_parse_progress_line()
    test_parse_ignores_plain_log()
    test_format_duration()
    test_eta_from_pct()
    test_is_progress_noise()
    test_remaining_text_unknown()
    test_parse_clamav_progress_redraw()
    test_merge_keeps_step()
    test_human_bytes()
    print("OK")

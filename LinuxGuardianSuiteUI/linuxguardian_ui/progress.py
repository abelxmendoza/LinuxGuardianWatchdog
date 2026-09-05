"""Parse LG_PROGRESS lines and format durations for the dashboard."""
from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass
class Progress:
    phase: str = ""
    message: str = ""
    pct: float | None = None
    done: int | None = None
    total: int | None = None
    eta_sec: int | None = None
    current: str = ""
    step: int | None = None
    steps: int | None = None


_PHASE_LABELS = {
    "clamav": "ClamAV malware scan",
    "rkhunter": "Rootkit scan",
    "integrity": "File integrity check",
    "audit": "Security audit",
}


_TOOL_PCT = re.compile(r"(\d{1,3}(?:\.\d+)?)%")
_TOOL_ETA = re.compile(r"(?:ETA|remaining)[:\s]*(\d{1,2}):(\d{2})(?::(\d{2}))?", re.I)


def parse_progress_line(line: str) -> Progress | None:
    if line.startswith("LG_PROGRESS"):
        return _parse_lg_progress(line)
    return parse_tool_progress(line)


def _parse_lg_progress(line: str) -> Progress | None:
    if not line.startswith("LG_PROGRESS"):
        return None
    payload = line[len("LG_PROGRESS") :].lstrip("|")
    fields: dict[str, str] = {}
    for part in payload.split("|"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        if key:
            fields[key] = value
    pct = _maybe_float(fields.get("pct"))
    if pct is not None:
        pct = max(0.0, min(100.0, pct))
    return Progress(
        phase=fields.get("phase", ""),
        message=fields.get("message", ""),
        pct=pct,
        done=_maybe_int(fields.get("done")),
        total=_maybe_int(fields.get("total")),
        eta_sec=_maybe_int(fields.get("eta_sec")),
        current=fields.get("current", ""),
        step=_maybe_int(fields.get("step")),
        steps=_maybe_int(fields.get("steps")),
    )


def parse_tool_progress(line: str) -> Progress | None:
    """Best-effort parse of ClamAV --progress / verbose redraws."""
    if "FOUND" in line or line.startswith("["):
        return None
    pct = None
    match = _TOOL_PCT.search(line)
    if match:
        pct = max(0.0, min(100.0, float(match.group(1))))
    eta_sec = None
    eta_match = _TOOL_ETA.search(line)
    if eta_match:
        hours_or_min = int(eta_match.group(1))
        mins_or_sec = int(eta_match.group(2))
        if eta_match.group(3) is not None:
            eta_sec = hours_or_min * 3600 + mins_or_sec * 60 + int(eta_match.group(3))
        else:
            eta_sec = hours_or_min * 60 + mins_or_sec
    current = ""
    if re.match(r"Scanning\s+/\S", line):
        current = re.sub(r"^Scanning\s+", "", line).strip()
    if pct is None and eta_sec is None and not current:
        return None
    return Progress(pct=pct, eta_sec=eta_sec, current=current)


def merge_progress(previous: Progress | None, incoming: Progress) -> Progress:
    if previous is None:
        return incoming
    return Progress(
        phase=incoming.phase or previous.phase,
        message=incoming.message or previous.message,
        pct=incoming.pct if incoming.pct is not None else previous.pct,
        done=incoming.done if incoming.done is not None else previous.done,
        total=incoming.total if incoming.total is not None else previous.total,
        eta_sec=incoming.eta_sec if incoming.eta_sec is not None else previous.eta_sec,
        current=incoming.current or previous.current,
        step=incoming.step if incoming.step is not None else previous.step,
        steps=incoming.steps if incoming.steps is not None else previous.steps,
    )


def format_duration(seconds: float) -> str:
    s = max(0, int(seconds))
    hours, rem = divmod(s, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{s}s"


def eta_from_pct(elapsed_sec: float, pct: float) -> int | None:
    if pct <= 0 or pct >= 100 or elapsed_sec <= 0:
        return None
    return int(elapsed_sec * (100.0 - pct) / pct)


def overall_fraction(progress: Progress) -> float | None:
    """Map phase-local percent onto 0..1 across steps when possible."""
    if progress.pct is None:
        return None
    local = progress.pct / 100.0
    if progress.step and progress.steps and progress.steps > 0:
        step = min(max(progress.step, 1), progress.steps)
        return ((step - 1) + local) / progress.steps
    return local


def phase_label(phase: str) -> str:
    if not phase:
        return "Working"
    return _PHASE_LABELS.get(phase, phase.replace("-", " ").title())


def is_progress_noise(line: str) -> bool:
    """True for machine progress / CR-redraw lines that shouldn't fill the log."""
    if line.startswith("LG_PROGRESS"):
        return True
    stripped = line.strip()
    if re.fullmatch(r"\d{1,3}(?:\.\d+)?%", stripped):
        return True
    if re.search(r"^\s*\[[=\-#>\s]*\]\s*\d{1,3}%", stripped):
        return True
    if re.search(r"\d{1,3}%", stripped) and re.search(r"\bETA\b", stripped, re.I):
        return True
    return False


def remaining_text(elapsed_sec: float, progress: Progress | None) -> str:
    if progress is None:
        return "Still running — waiting for the scanner to report progress"
    step_note = ""
    if progress.step and progress.steps and progress.step < progress.steps:
        step_note = " in this step"
    if progress.eta_sec is not None:
        if progress.eta_sec <= 0:
            return "Finishing up…"
        return f"About {format_duration(progress.eta_sec)} remaining{step_note}"
    frac = overall_fraction(progress)
    if frac is not None and 0 < frac < 1:
        eta = eta_from_pct(elapsed_sec, frac * 100.0)
        if eta is not None:
            return f"About {format_duration(eta)} remaining"
    return "Still running — remaining time unknown until the scanner reports %"


def _maybe_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except ValueError:
        return None


def _maybe_float(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None

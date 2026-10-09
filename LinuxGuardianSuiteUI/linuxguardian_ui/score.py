"""Parse the audit's summary. The percentage is computed once, in linux_security_audit.sh
(a warning is worth half a pass), and only read here, so the CLI and the app can't disagree."""
from __future__ import annotations

import re
from dataclasses import dataclass

_SCORE_RE = re.compile(r"Score:\s*(\d+) pass,\s*(\d+) warn,\s*(\d+) fail \(of (\d+) checks\)")
_RATING_RE = re.compile(r"^\s*Rating:\s*(\d+) of 100")


@dataclass(frozen=True)
class AuditScore:
    percent: int
    passed: int
    warned: int
    failed: int
    total: int


def parse_audit_score(lines: list[str]) -> AuditScore | None:
    counts = percent = None
    for line in lines:
        if counts is None and (m := _SCORE_RE.search(line)):
            counts = tuple(int(x) for x in m.groups())
        if percent is None and (m := _RATING_RE.search(line)):
            percent = int(m.group(1))
    if counts is None or percent is None:
        return None
    passed, warned, failed, total = counts
    return AuditScore(percent, passed, warned, failed, total)

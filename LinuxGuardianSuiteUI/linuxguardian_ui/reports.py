"""Plain-text diagnostic reports; raw evidence remains separate from interpretation."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import json
from pathlib import Path
import re

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


@dataclass
class ActivityReport:
    title: str
    command: str
    started: str = field(default_factory=timestamp)
    lines: list[str] = field(default_factory=list)
    exit_code: int | None = None
    finished: bool = False

    @property
    def state(self) -> str:
        if not self.finished:
            return "In progress — partial output"
        if self.exit_code is None:
            return "Ended — exit status unavailable"
        if self.exit_code == 130:
            return "Stopped — coverage may be incomplete"
        return f"Finished — exit code {self.exit_code}"

    def groups(self) -> dict[str, list[str]]:
        groups: dict[str, list[str]] = {"Needs attention": [], "Passed checks": [], "Activity & observations": []}
        for raw in self.lines:
            line = ANSI.sub("", raw).strip()
            if not line or line.startswith(("LG_PROGRESS|", "$", "====")):
                continue
            if re.search(r"\[(?:WARN|FAIL|ERROR)\]", line, re.I) or line.endswith(" FOUND"):
                key = "Needs attention"
            elif re.match(r"\[\s*OK\s*\]", line):
                key = "Passed checks" if self.title == "Security audit" else "Activity & observations"
            else:
                key = "Activity & observations"
            if line not in groups[key]:
                groups[key].append(line)
        return groups

    def summary(self, compact: bool = False) -> str:
        groups = self.groups()
        attention = groups["Needs attention"]
        lead = (f"{len(attention)} item(s) need review. Warnings can mean missing evidence or incomplete checks; they do not prove infection."
                if attention else "No warning lines captured so far. This does not establish that the machine is secure.")
        if self.finished and self.exit_code not in (0, None):
            lead = "This action stopped or returned a nonzero exit code. Review its output before relying on the result.\n" + lead
        parts = [self.title, self.state, lead]
        for title, lines in groups.items():
            if lines:
                parts.extend(["", title, *[f"• {line}" for line in (lines[:6] if compact else lines)]])
                if compact and len(lines) > 6:
                    parts.append(f"+ {len(lines) - 6} more — available in Terminal output and Copy All Activity")
        if self.title == "Security audit":
            parts.extend(["", "What these checks mean",
                          "Network access — firewall and SSH checks concern who can connect.",
                          "Updates & protection — updates and AppArmor help reduce exposure.",
                          "Data & administrator access — encryption and sudo checks concern stored data and elevated privileges."])
        parts.extend(["", "Next steps", self.next_steps()])
        return "\n".join(parts)

    def next_steps(self) -> str:
        if self.title == "Security audit":
            return "Review warnings first. Unverified checks need evidence, not automatic changes. Check update history and firewall rules; preserve required remote access. The score is a checklist, not a security guarantee."
        if "integrity" in self.title.lower():
            return "Compare changed paths with edits or updates you expected. Do not reset the baseline merely to dismiss changes. A baseline records a state; backups provide recovery."
        if self.title in ("End process", "Force Kill", "Close app process", "Process inventory"):
            return "Review exit codes, executable paths, parent processes, and listening sockets. An unknown name or open port alone does not establish a threat. A successful signal request does not prove the process exited."
        if "cache" in self.title.lower():
            return "Review categories, paths, and errors before clearing anything. Cache cleanup reclaims storage; it does not remove malware or establish system security."
        return "Review detections, skipped tools, permission errors, and scan scope. A completed command is not proof that every check ran. Investigate findings before deleting files."

    def export(self) -> str:
        raw = "\n".join(ANSI.sub("", line) for line in self.lines)
        return (f"# {self.title}\nStarted: {self.started}\nCommand: {self.command}\n\n"
                f"## High-level summary\n{self.summary()}\n\n## Terminal output (all captured lines)\n{raw}\n")


def export_session(reports: list[ActivityReport]) -> str:
    if not reports:
        return ""
    return ("LinuxGuardian — activity report\nScope: actions captured during this app session.\n"
            "Includes local paths and command details; review before sharing.\n\n" +
            "\n".join(report.export() for report in reports))


def export_saved_scan(data: dict | None) -> str:
    if not data:
        return ""
    parts = ["LinuxGuardian — last saved scan", "Scope: saved scan metadata and available scanner reports.",
             "Review target, errors, and each scanner's exit code; zero detections does not establish complete coverage.",
             "\n## Technical metadata", json.dumps(data, indent=2, ensure_ascii=False)]
    for key, title in (("report", "ClamAV terminal output"), ("rk_report", "Rootkit terminal output")):
        parts.append(f"\n## {title}")
        if not data.get(key):
            parts.append("No report path recorded.")
            continue
        try:
            parts.append(Path(data[key]).read_text(errors="replace"))
        except (OSError, ValueError) as exc:
            parts.append(f"Report unavailable: {exc}")
    return "\n".join(parts) + "\n"


def export_card(card) -> str:
    """All structured findings, including items omitted from the on-screen preview."""
    lines = [f"## {card.title}", f"Status: {card.status}", card.summary]
    rows = sorted(card.rows, key=lambda row: audit_topic(row.text)[0]) if card.key == "audit" else card.rows
    last_topic = None
    for row in rows:
        if card.key == "audit":
            topic, explanation = audit_topic(row.text)
            if topic != last_topic:
                lines.extend([f"\n### {topic}", explanation])
                last_topic = topic
        lines.append(f"- [{row.kind}] {row.text}")
        if row.detail:
            lines.append(f"  {row.detail}")
    for group in card.groups:
        lines.extend([f"\n### {group.title}", group.explanation])
        lines.extend(f"- {item}" for item in group.items)
        lines.extend(f"- {title}: {why}" for title, why in group.extra)
    return "\n".join(lines) + "\n"


def audit_topic(text: str) -> tuple[str, str]:
    value = text.lower()
    if any(word in value for word in ('firewall', 'ssh', 'remote', 'vnc', 'port')):
        return 'Network & remote access', 'Who can reach this computer and which remote services are available.'
    if any(word in value for word in ('update', 'apparmor', 'selinux', 'clamav', 'rootkit')):
        return 'Updates & threat protection', 'Patching and security tools reduce exposure; verify checks actually ran.'
    if any(word in value for word in ('sudo', 'password', 'login', 'account')):
        return 'Accounts & administrator access', 'Who can sign in or make privileged changes.'
    if any(word in value for word in ('luks', 'encrypt', 'disk', 'boot', 'integrity')):
        return 'Data & system integrity', 'Protection for stored files and unexpected system changes.'
    return 'Other checks', 'Additional observations to review in context.'

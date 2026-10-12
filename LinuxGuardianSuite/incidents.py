#!/usr/bin/env python3
"""Turn a pile of sensor events into INCIDENTS a person can reason about.

One odd thing is a data point. A program that appeared, ran from /tmp, then connected out and added itself to startup
is a story. This groups events that share an entity (the same program, user, address or file) within a couple of hours,
names the story in plain language, says why it might matter AND why it is often harmless, and lists what to check next.
Deterministic rules, no AI: every claim here can be traced to the events that produced it.

  incidents.py [--json|--text] [--days N] [--all]
  incidents.py --ack ID | --unack ID

Test hook: LG_HOME.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

import timeline  # noqa: E402
from events import SEVERITIES, incident_dir  # noqa: E402

RANK = {"info": 0, "warning": 1, "critical": 2}
LINK_GAP = 2 * 3600                       # events about the same thing this close together are one story
SEED_EVENTS = {"file_new_persistence", "honeypot_read", "honeypot_modified"}
SEED_CATEGORIES = {"sensor", "malware"}
INTERPRETERS = {"python", "python2", "python3", "node", "nodejs", "bash", "sh", "dash", "zsh", "perl", "ruby", "java", "php", "env"}


@dataclass
class Obs:
    ts: float
    severity: str
    category: str
    event: str
    message: str
    entities: set[str] = field(default_factory=set)
    technique: str = ""
    stage: str = ""
    key: str = ""
    extra: dict = field(default_factory=dict)


def _generic(entity: str) -> bool:
    base = os.path.basename(entity).rstrip("0123456789.")
    return base in INTERPRETERS or entity in ("", "root", "0.0.0.0")


def load_observations(days: float = 7, directory: Path | None = None, now: float | None = None) -> list[Obs]:
    directory = directory or incident_dir()
    now = time.time() if now is None else now
    out: list[Obs] = []
    if not directory.is_dir():
        return out
    for path in directory.glob("*.json"):
        try:
            r = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(r, dict) or r.get("severity") not in SEVERITIES or not r.get("message") or r.get("status") == "resolved":
            continue
        ts = timeline._epoch(r, path)
        if ts < now - days * 86400:
            continue
        ents = {str(e) for e in (r.get("entity") or []) if e}
        for k in ("exe", "path", "user", "remote"):
            if r.get(k):
                ents.add(str(r[k]))
        out.append(Obs(ts, r["severity"], str(r.get("category") or "other"), str(r.get("event") or ""), str(r["message"]),
                       {e for e in ents if not _generic(e)}, str(r.get("technique") or ""), str(r.get("stage") or ""), str(r.get("key") or ""),
                       {k: v for k, v in r.items() if k not in ("timestamp", "category", "severity", "message", "status")}))
    return sorted(out, key=lambda o: o.ts)


def cluster(obs: list[Obs]) -> list[list[Obs]]:
    parent = list(range(len(obs)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    last_seen: dict[str, int] = {}
    for i, o in enumerate(obs):
        for e in o.entities:
            j = last_seen.get(e)
            if j is not None and o.ts - obs[j].ts <= LINK_GAP:
                parent[find(i)] = find(j)
            last_seen[e] = i
    groups: dict[int, list[Obs]] = {}
    for i, o in enumerate(obs):
        groups.setdefault(find(i), []).append(o)
    return list(groups.values())


# (events that must ALL be present) -> title, why it matters, why it is often harmless, what to check
STORIES: list[tuple[frozenset, str, str, str, list[str]]] = [
    (frozenset({"failed_logins", "__critical__"}), "Someone guessed their way in",
     "Many failed logins followed by a success from the same address is how password guessing ends when it works.",
     "A forgetful you, or a script of yours, can look the same. Check whether the address is yours.",
     ["last -n 20", "sudo grep -E 'Accepted|Failed' /var/log/auth.log | tail -50", "Change the account's password and check ~/.ssh/authorized_keys"]),
    (frozenset({"proc_masquerade"}), "A program is disguised as part of the system",
     "Real kernel threads have no program file. Something that fakes that name is hiding.",
     "Very rarely benign.", ["ls -l /proc/<pid>/exe", "sha256sum <the exe>", "Collect evidence, then stop the program from the Processes tab"]),
    (frozenset({"proc_from_tmp", "new_outbound_program"}), "A program running from a temporary folder is talking to the internet",
     "Software you installed lives in /usr, /opt or your home. A program in /tmp that calls out is the classic shape of a downloaded payload.",
     "Some installers and AppImages unpack to /tmp briefly. If you just ran an installer you know, it can be that.",
     ["Open the Processes tab and look at the program", "ss -tnp | grep <process>", "sha256sum <the exe>  (paste it into a malware-lookup site)"]),
    (frozenset({"new_local_command", "new_outbound_program"}), "A program installed outside apt started talking to the internet",
     "pip, npm, cargo and downloads can run code at install time, and supply-chain attacks hide in new packages.",
     "Usually benign if you just installed a developer tool yourself and it checks for updates or fetches data.",
     ["Did you install this? pip/npm/cargo history: cat ~/.bash_history | grep -E 'pip|npm|cargo' | tail", "Check where it connects (the evidence bundle lists it)", "Look the package up before trusting it"]),
    (frozenset({"new_user", "privilege_added"}), "A new account was given administrator rights",
     "Creating an admin account is how an intruder keeps access after you change your password.",
     "Benign only if you created it.", ["getent passwd | tail", "getent group sudo", "sudo grep -E 'useradd|usermod' /var/log/auth.log"]),
    (frozenset({"new_autostart", "proc_from_tmp"}), "Something installed itself to start automatically, from a temporary folder",
     "Persistence from /tmp means a program wants to come back after every reboot.", "Rare.",
     ["cat the new startup file", "Collect evidence", "Remove it only after you know what it is"]),
    (frozenset({"new_autostart"}), "Something added itself to your startup",
     "Programs that want to survive a reboot add startup entries, cron jobs or services.",
     "Installing apps does this legitimately (a package-owned entry is marked as such).",
     ["cat the new file", "systemctl --user list-unit-files | grep -i <name>", "Did you install something new today?"]),
    (frozenset({"proc_from_tmp"}), "A program is running from a temporary folder",
     "Legitimate software almost never runs from /tmp.", "AppImages and some installers use /tmp briefly.",
     ["Open the Processes tab", "ls -l /proc/<pid>/exe", "sha256sum <the exe>"]),
    (frozenset({"proc_deleted_exe"}), "A running program's file was deleted",
     "Malware deletes itself after launch to hide.", "Updaters replace files under /opt and your home while the old copy keeps running.",
     ["ls -l /proc/<pid>/exe", "Restart the program: if it comes back from a real install, it was an update"]),
    (frozenset({"failed_logins"}), "Repeated failed logins",
     "Someone, or a bot, is guessing passwords.", "Internet-facing SSH sees this constantly. It only matters if a login then succeeds.",
     ["last -n 20", "Is SSH exposed? See the Exposure tab"]),
    (frozenset({"suspicious_port"}), "A program connected to a port known for malware",
     "Ports like 4444 or 6667 are classic reverse-shell and botnet channels.", "Some games and dev tools use odd ports.",
     ["ss -tnp | grep <process>", "Collect evidence"]),
    (frozenset({"new_usb_composite"}), "A USB device that is both keyboard and storage was plugged in",
     "That combination is how 'BadUSB' devices type commands into your computer.", "Some legitimate dongles and docks are composite devices.",
     ["Unplug it if you don't recognise it", "lsusb -v for the device"]),
    (frozenset({"uid_zero"}), "An account was given root privileges", "uid 0 is the administrator.", "Never normal.", ["getent passwd | awk -F: '$3==0'"]),
    (frozenset({"honeypot_read"}), "The decoy file was opened",
     "The decoy exists only to catch snooping; opening it means a program or person went looking for passwords.",
     "Backup tools and file indexers can touch it.", ["Which program read it? Check the Processes tab and recent logins"]),
]


# Stories that are worth a warning even when every single event in them is only "info".
MIN_SEVERITY = {"A program installed outside apt started talking to the internet": "warning"}


@dataclass
class Incident:
    id: str
    title: str
    severity: str
    confidence: str
    first_ts: float
    last_ts: float
    count: int
    techniques: list[str]
    stages: list[str]
    entities: list[str]
    why: str
    benign: str
    next_steps: list[str]
    timeline: list[dict]
    acknowledged: bool = False
    pids: list[int] = field(default_factory=list)
    exes: list[str] = field(default_factory=list)


def _story(group: list[Obs]) -> tuple[str, str, str, list[str]]:
    names = {o.event for o in group}
    if any(o.event == "failed_logins" and o.severity == "critical" for o in group):
        names.add("__critical__")
    for needed, title, why, benign, steps in STORIES:
        if needed <= names:
            return title, why, benign, steps
    top = max(group, key=lambda o: (RANK[o.severity], o.ts))
    return top.message.split(". ")[0][:120], "A sensor noticed something unusual.", "It may be normal for what you were doing.", ["Open the evidence bundle"]


def _confidence(group: list[Obs]) -> str:
    stages = {o.stage for o in group if o.stage}
    sev = max(RANK[o.severity] for o in group)
    if sev == 2 or len(stages) >= 3 or (sev == 1 and len(stages) >= 2):
        return "high"
    if sev == 1 or len(stages) >= 2:
        return "medium"
    return "low"


def build(days: float = 7, directory: Path | None = None, now: float | None = None, include_acknowledged: bool = False) -> list[Incident]:
    obs = load_observations(days, directory, now)
    acks = timeline.load_acks()
    out: list[Incident] = []
    for group in cluster(obs):
        seeds = [o for o in group if o.category in SEED_CATEGORIES or o.event in SEED_EVENTS]
        if not seeds:
            continue
        sev = max(group, key=lambda o: RANK[o.severity]).severity
        sensors = [o for o in group if o.category == "sensor"]
        if RANK[sev] == 0 and len(sensors) < 2:
            continue                                   # a lone routine note is a Timeline entry, not an incident
        title, why, benign, steps = _story(group)
        if RANK[MIN_SEVERITY.get(title, "info")] > RANK[sev]:
            sev = MIN_SEVERITY[title]
        first, last = group[0], group[-1]
        iid = hashlib.sha1(f"{first.key or first.message}|{int(first.ts)}".encode()).hexdigest()[:10]
        ents = sorted({e for o in group for e in o.entities})
        inc = Incident(
            iid, title, sev, _confidence(group), first.ts, last.ts, len(group),
            sorted({o.technique for o in group if o.technique}), sorted({o.stage for o in group if o.stage}), ents[:8], why, benign, steps,
            [{"ts": o.ts, "severity": o.severity, "message": o.message, "event": o.event, "technique": o.technique} for o in group],
            pids=sorted({int(o.extra["pid"]) for o in group if str(o.extra.get("pid", "")).isdigit()}),
            exes=sorted({str(o.extra["exe"]) for o in group if o.extra.get("exe")}),
        )
        inc.acknowledged = f"incident:{iid}" in acks and last.ts <= acks[f"incident:{iid}"]
        if inc.acknowledged and not include_acknowledged:
            continue
        out.append(inc)
    return sorted(out, key=lambda i: (-RANK[i.severity], -i.last_ts))


def acknowledge(iid: str, now: float | None = None) -> None:
    timeline.acknowledge(f"incident:{iid}", now=now)


def unacknowledge(iid: str) -> None:
    timeline.unacknowledge(f"incident:{iid}")


def narrative(inc: Incident) -> str:
    """The whole story as plain text (also what 'Copy summary' puts on the clipboard)."""
    t = lambda ts: time.strftime("%b %d %H:%M", time.localtime(ts))  # noqa: E731
    lines = [f"{inc.title}", f"Severity: {inc.severity}   Confidence: {inc.confidence}   First seen: {t(inc.first_ts)}   Events: {inc.count}", "",
             "What happened:"]
    lines += [f"  {t(e['ts'])}  {e['message']}" for e in inc.timeline]
    lines += ["", f"Why it matters: {inc.why}", f"Why it may be harmless: {inc.benign}", "", "What to check:"] + [f"  - {s}" for s in inc.next_steps]
    if inc.techniques:
        lines += ["", "ATT&CK techniques: " + ", ".join(inc.techniques)]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--text", action="store_true")
    ap.add_argument("--days", type=float, default=7)
    ap.add_argument("--all", action="store_true", help="include reviewed incidents")
    ap.add_argument("--ack", metavar="ID")
    ap.add_argument("--unack", metavar="ID")
    a = ap.parse_args()
    if a.ack:
        acknowledge(a.ack)
        return 0
    if a.unack:
        unacknowledge(a.unack)
        return 0
    incs = build(a.days, include_acknowledged=a.all)
    if a.json:
        print(json.dumps([inc.__dict__ for inc in incs]))
    else:
        print("\n\n".join(narrative(i) for i in incs) if incs else "No open incidents.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

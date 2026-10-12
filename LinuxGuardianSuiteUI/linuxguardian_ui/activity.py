"""Turn a script's terminal output into something a person can read.

The scripts print lines meant for a terminal: `[ OK ]`, `[WARN]`, hundreds of `/usr/bin/cat   [ Warning ]` rows,
a ClamAV summary block. This module reads those lines as they stream and keeps a small structured picture instead:
a few CARDS ("Malware scan", "Rootkit check", "Security audit", ...), each with a one-line summary, a status and,
where it helps, GROUPS of related items with a plain-language explanation ("Changed system programs (81): normal
after updates, here's why"). The raw lines are never discarded by the UI; they live under "Technical details".

Pure Python, no GTK: the parser is unit-tested against real scan output.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_TAG = re.compile(r"^\[(INFO| OK |WARN|FAIL)\]\s?(.*)$")
_RK_RESULT = re.compile(r"^\s+(.+?)\s{2,}\[ ([A-Za-z ()/-]+?) \]\s*$")
_RK_SECTION = re.compile(r"^Checking (the )?(system commands|for rootkits|the network|the local host)\.\.\.\s*$")
_RK_SUBSECTION = re.compile(r"^\s+Performing (.+?)\s*$")
_KV = re.compile(r"^([A-Za-z][A-Za-z ]+?):\s+(.+?)\s*$")

STATUS_RANK = {"ok": 0, "info": 1, "running": 1, "warn": 2, "fail": 3}


@dataclass
class Row:
    kind: str                 # ok | warn | fail | info
    text: str
    detail: str = ""


@dataclass
class Group:
    key: str
    title: str
    level: str                # ok | warn | fail
    items: list[str] = field(default_factory=list)
    explanation: str = ""
    extra: list[tuple[str, str]] = field(default_factory=list)      # (item, plain-language explanation) pairs


@dataclass
class Card:
    key: str
    title: str
    status: str = "running"   # running | ok | warn | fail | info
    summary: str = ""
    rows: list[Row] = field(default_factory=list)
    groups: list[Group] = field(default_factory=list)


# What rkhunter's non-file warnings mean on a desktop. (regex on the check label) -> (friendly title, explanation, serious?)
RK_EXPLAIN: list[tuple[str, str, str, bool]] = [
    (r"shared memory", "Large shared-memory segments",
     "Programs use shared memory to talk to each other. Browsers and apps built on Electron (VS Code, Claude, Cursor, Chrome) trigger this all the time. Usually harmless.", False),
    (r"passwd file changes", "The list of user accounts changed",
     "Your account list differs from rkhunter's saved copy. Installing software often adds system users, so this is normal after updates. Worth a look only if you didn't install anything.", False),
    (r"group file changes", "The list of user groups changed",
     "Same as above, for groups. Normal after installing software.", False),
    (r"/dev for suspicious file types", "Unusual files in /dev",
     "Docker, virtual machines and GPU drivers (NVIDIA) create unusual entries in /dev. Usually harmless.", False),
    (r"hidden files and directories", "Hidden files in system folders",
     "Some packages (Java and others) leave hidden files such as /etc/.java. Usually harmless.", False),
    (r"promiscuous interfaces", "A network card is listening to all traffic",
     "Docker, VPNs and packet-capture tools do this on purpose. Worth checking if you didn't start such a tool.", False),
    (r"root equivalent|passwordless accounts|backdoor ports|login backdoors|sniffer log|suspicious directories|possible rootkit files|rootkit strings",
     "Possible sign of a compromise",
     "rkhunter flagged something it treats as a real warning sign. Don't ignore this: open rkhunter's log (sudo less /var/log/rkhunter.log) for the detail.", True),
]
RK_PLACE = {"system commands": "System programs", "for rootkits": "Known rootkits", "the network": "Network", "the local host": "This computer's setup"}
FINE = {"ok", "not found", "none found", "found", "not allowed", "allowed", "skipped", "unsupported"}


def _friendly_rk(label: str) -> tuple[str, str, bool]:
    for rx, title, why, serious in RK_EXPLAIN:
        if re.search(rx, label, re.I):
            return title, why, serious
    return (label.strip().rstrip(":"),
            "rkhunter flagged this check. The details are in its log (sudo less /var/log/rkhunter.log).", False)


def _clam_time(text: str) -> str:
    """'4.663 sec (0 m 4 s)' -> '5 s';  '7335.2 sec (122 m 15 s)' -> '2 h 2 min'."""
    m = re.match(r"^\s*([\d.]+)\s*sec", text)
    if not m:
        return ""
    secs = round(float(m.group(1)))
    if secs < 60:
        return f"{secs} s"
    if secs < 3600:
        return f"{secs // 60} min {secs % 60} s"
    return f"{secs // 3600} h {(secs % 3600) // 60} min"


class Activity:
    """Feed it output lines (feed), tell it how the job ended (finish), read cards()/headline()."""

    def __init__(self) -> None:
        self._cards: dict[str, Card] = {}
        self._order: list[str] = []
        self._mode = "generic"
        self._kv: dict[str, str] = {}
        self._rk_place = ""
        self._rk: dict = {"ok": 0, "warn": 0, "files_checked": 0, "files_changed": [], "other": [], "rootkits_checked": 0,
                          "known_found": 0, "places": {}, "suspect": 0, "possible": 0, "done": False, "sig_checked": 0}
        self._pending_audit: list[Row] = []
        self.exit_code: int | None = None
        self.lines_seen = 0
        self.job = ""
        self.verdict_notes: list[str] = []

    # ------------------------------------------------------------------ cards
    def _card(self, key: str, title: str) -> Card:
        if key not in self._cards:
            self._cards[key] = Card(key, title)
            self._order.append(key)
        return self._cards[key]

    def cards(self) -> list[Card]:
        out = []
        for k in self._order:
            c = self._cards[k]
            if k == "rk":
                self._finalize_rk(c)
            if k == "audit":
                self._finalize_audit(c)
            out.append(c)
        return out

    # ------------------------------------------------------------------- input
    def feed(self, raw: str) -> None:
        line = _ANSI.sub("", raw).rstrip("\n")
        self.lines_seen += 1
        if line.startswith("LG_PROGRESS"):
            return
        if self._mode == "rk":
            if self._feed_rk(line):
                return
        if self._mode == "clam":
            if self._feed_clam(line):
                return
        self._feed_generic(line)

    def finish(self, code: int) -> None:
        self.exit_code = code
        for c in self._cards.values():
            if c.status == "running":
                c.status = "info" if code == 0 else "fail"
        if "rk" in self._cards:
            self._finalize_rk(self._cards["rk"])

    # ----------------------------------------------------------------- generic
    def _feed_generic(self, line: str) -> None:
        if line.startswith("$ "):
            self.job = line[2:].strip()
            return
        if re.match(r"^-{5,} SCAN SUMMARY -{5,}$", line):
            self._mode, self._kv = "clam", {}
            self._card("clam", "Malware scan (ClamAV)")
            return
        if line.startswith("[ Rootkit Hunter version"):
            self._mode = "rk"
            self._card("rk", "Rootkit check (rkhunter)")
            return
        if line.startswith("LinuxGuardian Security Audit"):
            self._mode = "audit"
            self._card("audit", "Security audit")
            return
        if self._mode == "audit":
            self._feed_audit(line)
            return
        m = _TAG.match(line)
        if not m:
            m2 = re.match(r"^\s{4}(/\S.*)$", line)
            if m2 and "integrity" in self._cards and self._cards["integrity"].groups:
                self._cards["integrity"].groups[-1].items.append(m2.group(1))
                return
            self._feed_plain(line)
            return
        tag, text = m.group(1), m.group(2).strip()
        kind = {"INFO": "info", " OK ": "ok", "WARN": "warn", "FAIL": "fail"}[tag]
        self._tagged(kind, text)

    def _feed_plain(self, line: str) -> None:
        s = line.strip()
        if re.match(r"^Score:\s*\d+ pass", s):
            c = self._card("audit", "Security audit")
            m = re.search(r"(\d+) pass, (\d+) warn, (\d+) fail \(of (\d+) checks\)", s)
            if m:
                p, w, f, t = (int(x) for x in m.groups())
                c.summary = f"{p} of {t} checks passed" + (f", {w} could be better" if w else "") + (f", {f} need fixing" if f else "")
                c.status = "fail" if f else "warn" if w else "ok"
            self._mode = "generic"
        elif re.match(r"^Rating:\s*(\d+) of 100", s):
            m = re.match(r"^Rating:\s*(\d+) of 100", s)
            self.verdict_notes.append(f"Security rating {m.group(1)}%")
        elif re.match(r"^(Modified files|Missing files|New files)[^:]*:\s*\d+", s):
            self._integrity_group(s)
        elif m := re.search(r"\b(main|daily|bytecode)\.c[lv]d\b.*?(up-to-date|updated).*?version:\s*(\d+)", s):
            c = self._card("update", "Virus definitions")
            state = "already current" if m.group(2) == "up-to-date" else "updated"
            c.rows.append(Row("ok", f"{m.group(1).capitalize()} signatures: {state} (version {m.group(3)})"))
            c.status = "ok"

    def _integrity_group(self, s: str) -> None:
        m = re.match(r"^(Modified files|Missing files|New files)([^:]*):\s*(\d+)", s)
        c = self._card("integrity", "File integrity")
        kind, qualifier, n = m.group(1), m.group(2), m.group(3)
        persistence = "persistence" in qualifier or "start-up" in qualifier
        key = kind + ("-persist" if persistence else "")
        title = {"Modified files": "Files that changed", "Missing files": "Files that disappeared",
                 "New files": "New files in start-up locations" if persistence else "New files"}[kind]
        why = {"Modified files": "These files differ from your saved baseline. Fine if you edited them; suspicious if you didn't.",
               "Missing files": "In your baseline but gone now. Fine if you deleted them on purpose.",
               "New files": ("Programs start from these places (shell start-up, ssh keys, autostart). A new file you didn't add is the classic sign of something "
                             "trying to survive a reboot. Check each one." if persistence else "Added since the baseline: usually just new documents.")}[kind]
        warn = kind != "New files" or persistence
        c.groups.append(Group(key, f"{title} ({n})", "warn" if warn else "ok", [], why))
        if warn:
            c.status = "warn" if c.status != "fail" else "fail"
        c.summary = "Some watched files are different from your baseline." if any(g.level == "warn" for g in c.groups) else c.summary

    def _tagged(self, kind: str, text: str) -> None:
        if m := re.match(r"^Step (\d) of (\d) — (.+?)\.?$", text):
            self._mode = "generic"
            if "ClamAV" in m.group(3):
                self._card("clam", "Malware scan (ClamAV)").status = "running"
            elif "rkhunter" in m.group(3):
                self._card("rk", "Rootkit check (rkhunter)").status = "running"
            return
        if m := re.match(r"^Malware/rootkit scan of (.+?) started \((.+)\)\.$", text):
            self._card("clam", "Malware scan (ClamAV)").rows.append(Row("info", f"Scanning {m.group(1)} ({m.group(2)})"))
            return
        if m := re.match(r"^Changed-only: (\d+) file", text):
            self._card("clam", "Malware scan (ClamAV)").rows.append(Row("info", f"{m.group(1)} files changed since the last scan"))
            return
        if text.startswith(("Elapsed time updates", "Tip:", "Quick mode skips")):
            return
        if "rkhunter rootkit checks" in text and "elapsed" in text:
            return
        if text.startswith("rkhunter needs root"):
            self._card("rk", "Rootkit check (rkhunter)").rows.append(Row("info", "Needs administrator approval (your desktop shows the password prompt; this app never sees it)"))
            return
        if text.startswith("ClamAV:") or text.startswith("ClamAV found") or text.startswith("ClamAV exited"):
            c = self._card("clam", "Malware scan (ClamAV)")
            c.status = {"ok": "ok", "warn": "warn", "fail": "fail", "info": "info"}[kind]
            if kind == "warn" and "found" in text:
                c.status = "fail"
            self._clam_summary_line(c, text)
            return
        if text.startswith("rkhunter reported") or text.startswith("rkhunter: no warnings") or text.startswith("rkhunter exited"):
            return                                                    # judged from the output itself, not from this echo
        if text.startswith(("Rootkit check skipped", "No way to ask", "This result covers malware only")):
            c = self._card("rk", "Rootkit check (rkhunter)")
            c.status = "info"
            c.summary = "Skipped: needs administrator rights"
            c.rows.append(Row("info", text))
            return
        if text.startswith(("Cancelled", "Rootkit check cancelled")):
            c = self._card("rk" if "rootkit" in text.lower() else "update", "Rootkit check (rkhunter)" if "rootkit" in text.lower() else "Password prompt")
            c.status, c.summary = "info", "Cancelled: you dismissed the password prompt. Nothing was changed."
            c.rows = []
            return
        if text.startswith("Scan result saved"):
            return
        if text.startswith("Malware/rootkit scan complete"):
            return
        if re.match(r"^(Modified files|Missing files|New files)[^:]*:\s*\d+", text):
            self._integrity_group(text)
            return
        if text.startswith(("Updating ClamAV", "Running freshclam")):
            self._card("update", "Virus definitions").rows.append(Row("info", "Downloading the latest virus definitions…"))
            return
        if text.startswith("Virus definitions are up to date"):
            c = self._card("update", "Virus definitions")
            c.status, c.summary = "ok", "Virus definitions are up to date."
            return
        if text.startswith(("Building integrity baseline", "Checking current state")):
            self._card("integrity", "File integrity").rows.append(Row("info", text))
            return
        if text.startswith(("Honeypot file was", "The honeypot file")):
            c = self._card("integrity", "File integrity")
            c.rows.append(Row("fail", "The decoy file was touched: something read or changed it."))
            c.status = "fail"
            return
        if "No changes detected" in text:
            c = self._card("integrity", "File integrity")
            c.status, c.summary = "ok", "Nothing changed: your watched files match the baseline."
            return
        if text.startswith(("Baseline written", "Baseline complete")):
            c = self._card("integrity", "File integrity")
            c.status, c.summary = "ok", text
            return
        # Anything else tagged becomes a plain row on the most recent card (or a general card).
        key = self._order[-1] if self._order else "general"
        c = self._card(key, "Details") if key == "general" else self._cards[key]
        c.rows.append(Row(kind, text))
        if kind in ("warn", "fail") and STATUS_RANK[kind] > STATUS_RANK.get(c.status, 0):
            c.status = kind
        elif kind == "ok" and c.status == "running":
            c.status = "ok"

    # ------------------------------------------------------------------ ClamAV
    def _feed_clam(self, line: str) -> bool:
        if not line.strip() or _TAG.match(line):
            self._finish_clam_block()
            return False
        m = _KV.match(line)
        if m:
            self._kv[m.group(1).strip().lower()] = m.group(2)
            return True
        return False

    def _finish_clam_block(self) -> None:
        self._mode = "generic"
        c = self._card("clam", "Malware scan (ClamAV)")
        self._clam_summary_line(c, "")

    def _clam_summary_line(self, c: Card, text: str) -> None:
        kv = self._kv
        if not kv:
            if text and not c.summary:
                c.summary = "No malware found." if c.status == "ok" else text
            return
        files = kv.get("scanned files", "?")
        infected = int(re.sub(r"\D", "", kv.get("infected files", "0")) or 0)
        parts = [f"{files} files checked", f"{infected} infected" if infected else "nothing infected"]
        took = _clam_time(kv.get("time", ""))
        if took:
            parts.append(took)
        c.summary = " · ".join(parts)
        if infected:
            c.status = "fail"
        elif c.status in ("running", "info"):
            c.status = "ok"
        c.rows = [r for r in c.rows if not r.text.startswith(("Signature database", "Data scanned"))]
        if kv.get("known viruses"):
            known = int(re.sub(r"\D", "", kv["known viruses"]) or 0)
            c.rows.append(Row("info", f"Signature database: {known:,} known threats (engine {kv.get('engine version', '?')})"))
        if kv.get("data scanned"):
            c.rows.append(Row("info", f"Data scanned: {kv['data scanned']}"))

    # ---------------------------------------------------------------- rkhunter
    def _feed_rk(self, line: str) -> bool:
        rk = self._rk
        if re.match(r"^System checks summary", line):
            rk["summary_mode"] = True
            return True
        if rk.get("summary_mode"):
            m = re.match(r"^\s+(Files checked|Suspect files|Rootkits checked|Possible rootkits)\s*:\s*(\d+)", line)
            if m:
                key = m.group(1)
                n = int(m.group(2))
                if key == "Files checked":
                    rk["files_checked"] = n
                elif key == "Suspect files":
                    rk["suspect"] = n
                elif key == "Rootkits checked":
                    rk["rootkits_checked"] = n
                else:
                    rk["possible"] = n
                return True
            if _TAG.match(line):
                rk["done"] = True
                self._mode = "generic"
                return False
            return True
        m = _RK_SECTION.match(line)
        if m:
            self._rk_place = RK_PLACE[m.group(2)]
            rk["places"].setdefault(self._rk_place, {"ok": 0, "warn": 0})
            return True
        if _TAG.match(line):
            if line.startswith("[INFO] rkhunter rootkit checks") or "elapsed, still running" in line:
                return True                                           # periodic heartbeat, shown by the progress bar
            rk["done"] = True
            self._mode = "generic"
            return False
        m = _RK_SUBSECTION.match(line)
        if m:
            self._rk_sub = m.group(1)
            return True
        m = _RK_RESULT.match(line)
        if m:
            label, result = m.group(1).strip(), m.group(2).strip()
            place = rk["places"].setdefault(self._rk_place or "Other", {"ok": 0, "warn": 0})
            if result.lower() == "warning":
                place["warn"] += 1
                rk["warn"] += 1
                if label.startswith("/"):
                    rk["files_changed"].append(label)
                else:
                    rk["other"].append(label)
            else:
                place["ok"] += 1
                rk["ok"] += 1
                if getattr(self, "_rk_sub", "") .startswith("check of known rootkit") and result.lower() == "not found":
                    rk["sig_checked"] += 1
            return True
        return True

    def _finalize_rk(self, c: Card) -> None:
        rk = self._rk
        if not (rk["ok"] or rk["warn"] or rk["done"]):
            return
        c.groups = []
        n_files, n_other = len(rk["files_changed"]), len(rk["other"])
        checked = rk["files_checked"]
        sig = rk["rootkits_checked"] or rk["sig_checked"]
        bits = []
        if checked:
            bits.append(f"{checked} system programs")
        if sig:
            bits.append(f"{sig} known rootkits")
        c.summary = ("Checked " + " and ".join(bits) + ". " if bits else "") + (
            "No warnings." if not rk["warn"] else f"{rk['warn']} warning{'s' if rk['warn'] != 1 else ''}: {n_files} changed program{'s' if n_files != 1 else ''}"
            + (f", {n_other} unusual thing{'s' if n_other != 1 else ''}." if n_other else "."))
        if n_files:
            c.groups.append(Group("changed_files", f"System programs that differ from rkhunter's saved copy ({n_files})", "warn", list(rk["files_changed"]),
                                  "rkhunter keeps a saved copy ('baseline') of what your system programs looked like. After software updates they legitimately change, "
                                  "and on Ubuntu this copy isn't refreshed automatically, so a long list is expected. "
                                  "To confirm they are only updates, use “Review rootkit baseline” in Scanner health: it checks each one against its official Ubuntu package."))
        seen = set()
        extras: list[tuple[str, str]] = []
        serious = False
        for label in rk["other"]:
            title, why, ser = _friendly_rk(label)
            serious = serious or ser
            if title in seen:
                continue
            seen.add(title)
            extras.append((title, why))
        if extras:
            c.groups.append(Group("unusual", f"Unusual things rkhunter flagged ({len(extras)})", "fail" if serious else "warn",
                                  [t for t, _ in extras], "These are common on desktop Linux and are usually harmless, but each is explained so you can judge.", extras))
        ok_places = [f"{p}: {v['ok']} checks fine" + (f", {v['warn']} flagged" if v["warn"] else "") for p, v in rk["places"].items() if v["ok"] or v["warn"]]
        if ok_places:
            c.groups.append(Group("passed", f"What was checked ({rk['ok'] + rk['warn']} checks)", "ok", ok_places,
                                  "Each area rkhunter looked at." + (f" None of the {sig} known rootkits were found." if sig and not rk["possible"] and not serious else "")))
        c.status = "fail" if serious else ("warn" if rk["warn"] else "ok")
        if self.exit_code is None and not rk["done"]:
            c.status = "running"                       # results so far, but rkhunter is still working
        c.rows = []                                   # the approval note is moot once there are results

    # ---------------------------------------------------------------- audit
    def _feed_audit(self, line: str) -> None:
        s = line.strip()
        if re.match(r"^=+$", s) or not s:
            return
        if re.match(r"^Score:", s) or re.match(r"^Rating:", s):
            self._feed_plain(line)
            if s.startswith("Score:"):
                self._mode = "generic"
            return
        m = _TAG.match(line)
        if m:
            kind = {"INFO": "info", " OK ": "ok", "WARN": "warn", "FAIL": "fail"}[m.group(1)]
            text = m.group(2).strip()
            main, _, advice = text.partition(" — ")
            c = self._cards["audit"]
            c.rows.append(Row(kind, main, advice))
            c._raw_rows = c.rows                # type: ignore[attr-defined]
        elif s.startswith("Update configuration does not prove"):
            return

    def _finalize_audit(self, c: Card) -> None:
        """Problems stay visible as rows; everything that passed is folded into one quiet group."""
        raw = getattr(c, "_raw_rows", None)
        if raw is None:
            raw = c._raw_rows = c.rows          # type: ignore[attr-defined]
        problems = [r for r in raw if r.kind in ("warn", "fail")]
        passed = [r.text for r in raw if r.kind == "ok"]
        c.rows = problems
        c.groups = [Group("passed", f"Passed ({len(passed)})", "ok", passed, "Checks that are in good shape.")] if passed else []
        if self.verdict_notes and c.summary and "rating" not in c.summary:
            note = next((n for n in self.verdict_notes if n.startswith("Security rating")), "")
            if note:
                c.summary += f" · {note.lower()}"

    # -------------------------------------------------------------- verdict
    def headline(self) -> tuple[str, str]:
        """(level, one sentence) for the top of the activity view."""
        cards = self.cards()
        if not cards:
            return "info", "Starting…" if self.exit_code is None else "Finished."
        worst = max(cards, key=lambda c: STATUS_RANK.get(c.status, 0))
        running = [c for c in cards if c.status == "running"]
        if self.exit_code is None and running:
            return "info", "Working on: " + ", ".join(c.title for c in running)
        clam, rk = self._cards.get("clam"), self._cards.get("rk")
        if clam is not None or rk is not None:
            return self._scan_headline(clam, rk)
        if worst.status == "fail":
            return "fail", f"{worst.title}: needs attention. {worst.summary}".strip()
        if worst.status == "warn":
            return "warn", f"{worst.title}: {worst.summary or 'a few things to review.'}".strip()
        done = cards[-1]
        return "ok", (done.summary or f"{done.title} finished.")

    def _scan_headline(self, clam: Card | None, rk: Card | None) -> tuple[str, str]:
        if clam is not None and clam.status == "fail":
            return "fail", "ClamAV found an infected file. See the Malware scan card."
        parts = []
        level = "ok"
        if clam is not None and clam.status == "ok":
            parts.append("no malware found")
        elif clam is not None and clam.status == "warn":
            parts.append("malware scan finished with warnings")
            level = "warn"
        if rk is not None:
            if rk.status == "fail":
                parts.append("rkhunter flagged something serious")
                level = "fail"
            elif rk.status == "warn":
                n = self._rk["warn"]
                benign = len(self._rk["files_changed"])
                parts.append(f"{n} rkhunter warning{'s' if n != 1 else ''} to review ({benign} are changed programs, usually just updates)")
                level = "warn" if level != "fail" else level
            elif rk.status == "info" and "Skipped" in rk.summary:
                parts.append("rootkit check skipped")
                level = "warn" if level == "ok" else level
            elif rk.status == "info":
                parts.append("rootkit check cancelled")
                level = "warn" if level == "ok" else level
            elif rk.status == "ok":
                parts.append("no rootkit warnings")
        text = "Scan finished: " + ", ".join(parts) + "." if parts else "Scan finished."
        return level, text[0].upper() + text[1:]

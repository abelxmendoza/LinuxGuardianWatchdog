"""Incidents tab: the blue team's view. Live monitoring status, open incidents (stories, not log lines), and the full Timeline.

Everything here is read-only observation. "Collect evidence" copies facts into a private folder; "Mark reviewed" and
"This is expected" only change what LinuxGuardian reports. Nothing is stopped, blocked or deleted from this page.
"""
from __future__ import annotations

import json
import time

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, Gtk, Pango  # noqa: E402

from linuxguardian_ui import scan_history  # noqa: E402,F401  (puts the suite dir on sys.path)
from linuxguardian_ui.clipboard import copy_text  # noqa: E402
from linuxguardian_ui.components import copy_action, widget_report, page_header, section_header  # noqa: E402
from linuxguardian_ui.dialogs import confirm  # noqa: E402
from linuxguardian_ui.pages.ai_dialogs import AiSettingsWindow, InvestigationWindow  # noqa: E402
from linuxguardian_ui.pages.coverage_view import CoverageView  # noqa: E402
from linuxguardian_ui.pages.timeline import TimelinePage  # noqa: E402
from linuxguardian_ui.scripts import run_sync_async  # noqa: E402

SEV = {"critical": ("Critical", "omega-critical"), "warning": ("Suspicious", "omega-warning"), "info": ("Note", "omega-dim")}
CONF = {"high": "Strong signs", "medium": "Some signs", "low": "Weak signs"}


def _label(text: str, css: str | None = None, *, selectable: bool = False, mono: bool = False) -> Gtk.Label:
    label = Gtk.Label(label=text, xalign=0, wrap=True, selectable=selectable)
    label.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
    if css:
        label.add_css_class(css)
    if mono:
        label.add_css_class("update-raw")
    return label


def _when(ts: float) -> str:
    return time.strftime("%b %d, %H:%M", time.localtime(ts)).replace(" 0", " ")


def _ago(ts: float | None) -> str:
    if not ts:
        return "never"
    s = max(0, time.time() - ts)
    return "just now" if s < 90 else f"{int(s // 60)} min ago" if s < 5400 else f"{int(s // 3600)} h ago" if s < 172800 else f"{int(s // 86400)} days ago"


class IncidentsView(Gtk.Box):
    def __init__(self, toast_overlay: Adw.ToastOverlay) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self._toast_overlay = toast_overlay
        self._busy = False
        self._status: dict = {}
        self.status_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.status_card.add_css_class("omega-card")
        self.append(self.status_card)
        self.append(section_header("Open incidents"))
        self.list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.append(self.list_box)
        self.show_reviewed = Gtk.CheckButton(label="Also show incidents I've reviewed")
        self.show_reviewed.connect("toggled", lambda *_: self.refresh())
        self.append(self.show_reviewed)
        self.refresh()

    @staticmethod
    def _clear(box: Gtk.Box) -> None:
        child = box.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            box.remove(child)
            child = nxt

    # ---- loading --------------------------------------------------------------
    def refresh(self) -> None:
        def got_status(code: int, lines: list[str]) -> None:
            try:
                self._status = json.loads("".join(lines))
            except json.JSONDecodeError:
                self._status = {}
            self._render_status()

        def got_incidents(code: int, lines: list[str]) -> None:
            try:
                incs = json.loads("".join(lines))
            except json.JSONDecodeError:
                incs = []
            self._render_incidents(incs)

        run_sync_async("sensors.py", ["--status", "--json"], got_status, timeout=30.0)
        args = ["--json"] + (["--all"] if self.show_reviewed.get_active() else [])
        run_sync_async("incidents.py", args, got_incidents, timeout=30.0)

    # ---- status ----------------------------------------------------------------
    def _render_status(self) -> None:
        self._clear(self.status_card)
        s = self._status
        sensors = s.get("sensors", [])
        working = sum(1 for x in sensors if x["ok"])
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.status_card.append(head)
        active = bool(s.get("active"))
        timer_on = s.get("timer") is True
        dot = Gtk.Label(label="●" if (active and timer_on) else "○")
        dot.add_css_class("title-2")
        dot.add_css_class("omega-heading" if (active and timer_on) else "omega-dim")
        head.append(dot)
        title = Gtk.Label(label=("Live monitoring is on" if timer_on else "Live monitoring is off: sensors only run when you press Check now")
                          if active else "Live monitoring hasn't run yet", xalign=0, hexpand=True)
        title.add_css_class("update-name")
        head.append(title)
        check = Gtk.Button(label="Check now")
        check.connect("clicked", self._on_check_now)
        head.append(check)
        ai_settings = Gtk.Button(label="AI settings")
        ai_settings.connect("clicked", lambda _b: AiSettingsWindow(self.get_root(), self._toast_overlay).present())
        head.append(ai_settings)
        if not timer_on:
            turn_on = Gtk.Button(label="Turn on live monitoring")
            turn_on.add_css_class("suggested-action")
            turn_on.connect("clicked", self._on_turn_on)
            head.append(turn_on)
        if active:
            line = f"{working} of {len(sensors)} sensors working · last check {_ago(s.get('last_run'))}"
            self.status_card.append(_label(line, "omega-dim"))
        else:
            self.status_card.append(_label("The sensors watch for what an attack does while it happens: guessed logins, programs running from /tmp, a new "
                                           "program calling the internet, something adding itself to startup. They only observe.", "omega-dim"))
        if s.get("learning") and s.get("learning_until"):
            self.status_card.append(_label(f"Learning what's normal on this laptop until {_when(s['learning_until'])}. During this time the network "
                                           "sensor stays quiet so it doesn't cry wolf; the others already alert.", "omega-warning"))
        self._render_intel(s.get("threat_intel") or {})
        self._render_decoys(s.get("decoys") or {})
        problems = [x for x in sensors if x["ok"] is False]
        if problems:
            ex = Gtk.Expander(label=f"{len(problems)} sensor(s) can't work fully")
            inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            for x in problems:
                inner.append(_label(f"{x['name']}: {x['error']}", "omega-warning", selectable=True))
            ex.set_child(inner)
            self.status_card.append(ex)

    def _render_intel(self, intel: dict) -> None:
        """One row for the free known-bad-address lists: what it does now, and the button to turn it on or refresh it."""
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        css = {"ok": "omega-heading", "warning": "omega-warning"}.get(intel.get("level"), "omega-dim")
        row.append(_label("Known-bad addresses: " + (intel.get("text") or "unavailable"), css))
        row.get_first_child().set_hexpand(True)
        on = bool(intel.get("enabled"))
        btn = Gtk.Button(label="Update lists" if on else "Download free lists")
        btn.set_tooltip_text("Downloads two free public lists of attacker and botnet addresses. Matching happens on this laptop only.")
        btn.connect("clicked", self._on_update_intel if on else self._on_enable_intel)
        row.append(btn)
        if on:
            off = Gtk.Button(label="Turn off")
            off.connect("clicked", self._on_intel_off)
            row.append(off)
        self.status_card.append(row)

    def _render_decoys(self, d: dict) -> None:
        """One row for the decoy files (fake secrets that raise a critical alert if something opens them)."""
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        planted = bool(d.get("planted"))
        row.append(_label("Decoy files: " + (d.get("text") or "unavailable"), "omega-heading" if planted else "omega-dim"))
        row.get_first_child().set_hexpand(True)
        if planted:
            off = Gtk.Button(label="Remove decoys")
            off.connect("clicked", lambda _b: confirm(self.get_root(), "Remove the decoy files?", "Only the fake files LinuxGuardian planted are removed, "
                        "and only if they are unchanged.", "Remove", lambda: run_sync_async("decoys.py", ["--remove"], lambda c, l: (self._toast(l[-1] if l else "Removed"), self.refresh()),
                                                                                           timeout=30.0), destructive=False))
            row.append(off)
        else:
            btn = Gtk.Button(label="Plant decoys…")
            btn.set_tooltip_text("Plants a fake SSH key, fake cloud credentials and a fake .env file. If anything opens them you get a critical alert.")
            btn.connect("clicked", self._on_plant_decoys)
            row.append(btn)
        self.status_card.append(row)

    def _on_plant_decoys(self, _btn: Gtk.Button) -> None:
        confirm(self.get_root(), "Plant decoy files?",
                "Three clearly fake files are created where an intruder looks for secrets: ~/.ssh/old_deploy_key, ~/.aws/credentials.bak and ~/.env.production.bak. "
                "They unlock nothing. If a program or person opens one, you get a critical alert (backup tools and file indexers can also trigger it, and "
                "LinuxGuardian's own scans are ignored). It can't say which program did it.\n\nNothing real is touched; a file that already has one of those names is left alone.",
                "Plant decoys", lambda: run_sync_async("decoys.py", ["--create"], lambda c, l: (self._toast(l[0] if l else "Done"), self.refresh()), timeout=30.0),
                destructive=False)

    def _on_enable_intel(self, btn: Gtk.Button) -> None:
        confirm(self.get_root(), "Check connections against known-bad addresses?",
                "LinuxGuardian will download two free, public lists (FireHOL level 1 from GitHub, and abuse.ch's Feodo Tracker). They contain "
                "internet addresses that researchers have flagged as attack sources or botnet control servers.\n\nThe lists are refreshed at most once a "
                "day while live monitoring runs. Matching happens on this laptop: none of your connections or addresses are ever sent anywhere. "
                "A match is reported as a critical finding; nothing is blocked.", "Download lists",
                lambda: self._run_intel_update(btn), destructive=False)

    def _on_update_intel(self, btn: Gtk.Button) -> None:
        self._run_intel_update(btn)

    def _run_intel_update(self, btn: Gtk.Button) -> None:
        btn.set_sensitive(False)

        def done(code: int, lines: list[str]) -> None:
            self._toast("Lists updated" if code == 0 else (lines[-1] if lines else "Couldn't download the lists"))
            self.refresh()

        run_sync_async("threat_intel.py", ["--update", "--force"], done, timeout=120.0)

    def _on_intel_off(self, _btn: Gtk.Button) -> None:
        confirm(self.get_root(), "Turn off known-bad address checking?",
                "The downloaded lists are deleted and connections are no longer compared against them.", "Turn off",
                lambda: run_sync_async("threat_intel.py", ["--off"], lambda c, l: (self._toast("Turned off"), self.refresh()), timeout=30.0),
                destructive=False)

    def _on_check_now(self, btn: Gtk.Button) -> None:
        btn.set_sensitive(False)

        def done(code: int, lines: list[str]) -> None:
            btn.set_sensitive(True)
            self._toast(lines[-1] if lines else "Checked")
            self.refresh()

        run_sync_async("sensors.py", ["--run"], done, timeout=90.0)

    def _on_turn_on(self, _btn: Gtk.Button) -> None:
        confirm(self.get_root(), "Turn on live monitoring?",
                "A small job will run as you every 5 minutes (no password needed). It checks login history, running programs, new network "
                "behaviour, startup entries, accounts and USB devices, and tells you about anything new and suspicious.\n\nIt only observes: it "
                "never stops, blocks or changes anything. You can turn it off from the Hardening page.", "Turn on",
                lambda: run_sync_async("hardening.py", ["--apply", "sensors_timer"], lambda c, l: (self._toast(l[-1] if l else "Done"), self.refresh()), timeout=90.0),
                destructive=False)

    # ---- incidents --------------------------------------------------------------
    def _render_incidents(self, incs: list[dict]) -> None:
        self._clear(self.list_box)
        if not incs:
            ok = Gtk.Label(label="No open incidents. Nothing suspicious has been seen." if self._status.get("active")
                           else "No incidents yet. Turn on live monitoring to start watching.", xalign=0)
            ok.add_css_class("omega-heading" if self._status.get("active") else "omega-dim")
            self.list_box.append(ok)
            return
        for inc in incs:
            self.list_box.append(self._card(inc))

    def _card(self, inc: dict) -> Gtk.Widget:
        text, css = SEV[inc["severity"]]
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        card.add_css_class("activity-card")
        card.add_css_class({"critical": "activity-fail", "warning": "activity-warn", "info": "activity-info"}[inc["severity"]])
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        card.append(head)
        chip = Gtk.Label(label=text, valign=Gtk.Align.START)
        chip.add_css_class("impact-badge")
        chip.add_css_class(css)
        head.append(chip)
        t = Gtk.Label(label=inc["title"], xalign=0, hexpand=True, wrap=True)
        t.add_css_class("activity-title")
        head.append(t)
        meta = f"{_when(inc['first_ts'])}" + (f" to {_when(inc['last_ts'])}" if inc["last_ts"] - inc["first_ts"] > 60 else "") + \
            f" · {inc['count']} event{'s' if inc['count'] != 1 else ''} · {CONF.get(inc['confidence'], '')}"
        card.append(_label(meta, "omega-dim"))

        what = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        card.append(what)
        what.append(_label("What happened", "update-name"))
        for e in inc["timeline"][:4]:
            what.append(_label(f"{time.strftime('%H:%M', time.localtime(e['ts']))}  {e['message']}"))
        if len(inc["timeline"]) > 4:
            ex = Gtk.Expander(label=f"{len(inc['timeline']) - 4} more events")
            col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
            for e in inc["timeline"][4:]:
                col.append(_label(f"{time.strftime('%H:%M', time.localtime(e['ts']))}  {e['message']}"))
            ex.set_child(col)
            what.append(ex)
        card.append(_label("Why it matters: " + inc["why"], "omega-dim"))
        card.append(_label("Why it may be harmless: " + inc["benign"], "omega-dim"))
        steps = Gtk.Expander(label="What to check")
        sc = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        for s in inc["next_steps"]:
            sc.append(_label("•  " + s, selectable=True, mono=s.startswith(("sudo", "ls ", "last", "ss ", "cat", "getent", "sha256", "systemctl", "lsusb"))))
        steps.set_child(sc)
        card.append(steps)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, margin_top=4)
        card.append(row)
        ai_btn = Gtk.Button(label="Investigate with AI…")
        ai_btn.add_css_class("suggested-action")
        ai_btn.set_tooltip_text("An optional assistant reads the redacted evidence and explains what it thinks. You see what is sent first; it can only suggest.")
        ai_btn.connect("clicked", lambda _b, i=inc: InvestigationWindow(self.get_root(), i, self._toast_overlay).present())
        row.append(ai_btn)
        ev = Gtk.Button(label="Collect evidence")
        ev.set_tooltip_text("Saves a read-only snapshot (processes, connections, logins, startup entries, program hashes) to a private folder.")
        ev.connect("clicked", lambda _b, i=inc: self._collect(i))
        row.append(ev)
        cp = Gtk.Button(label="Copy summary")
        cp.connect("clicked", lambda _b, i=inc: self._copy(i))
        row.append(cp)
        rv = Gtk.Button(label="Unmark reviewed" if inc.get("acknowledged") else "Mark reviewed")
        rv.connect("clicked", lambda _b, i=inc: self._review(i))
        row.append(rv)
        if inc["exes"] and not inc.get("acknowledged"):
            ex = Gtk.Button(label="This is expected…")
            ex.set_tooltip_text("Tells the sensors this program is fine so they stop reporting it.")
            ex.connect("clicked", lambda _b, i=inc: self._expected(i))
            row.append(ex)
        return card

    # ---- actions ------------------------------------------------------------------
    def _toast(self, text: str) -> None:
        self._toast_overlay.add_toast(Adw.Toast.new(text))

    def _collect(self, inc: dict) -> None:
        def done(code: int, lines: list[str]) -> None:
            if code != 0 or not lines:
                self._toast("Couldn't collect evidence: " + (lines[-1] if lines else "unknown error"))
                return
            path = lines[-1].strip()
            self._toast(f"Evidence saved to {path}")
            try:
                Gio.AppInfo.launch_default_for_uri("file://" + path, None)
            except Exception:  # noqa: BLE001 - opening the folder is a convenience
                pass

        run_sync_async("evidence.py", ["--incident", inc["id"]], done, timeout=90.0)

    def _copy(self, inc: dict) -> None:
        import incidents as backend

        try:
            copy_text(backend.narrative(backend.Incident(**{k: v for k, v in inc.items() if k in backend.Incident.__dataclass_fields__})))
            self._toast("Summary copied")
        except Exception as exc:  # noqa: BLE001
            self._toast(f"Copy failed: {exc}")

    def _review(self, inc: dict) -> None:
        flag = "--unack" if inc.get("acknowledged") else "--ack"
        run_sync_async("incidents.py", [flag, inc["id"]], lambda c, l: self.refresh(), timeout=30.0)

    def _expected(self, inc: dict) -> None:
        exes = inc["exes"]
        confirm(self.get_root(), "Treat this as expected?",
                "LinuxGuardian will stop reporting these programs:\n" + "\n".join("•  " + e for e in exes[:5]) +
                "\n\nOnly do this for software you recognise and trust. You can undo it by editing ~/.linuxguardian/sensors_allow.json.",
                "Treat as expected", lambda: self._do_expected(inc), destructive=False)

    def _do_expected(self, inc: dict) -> None:
        pending = {"n": len(inc["exes"])}

        def one_done(code: int, lines: list[str]) -> None:
            pending["n"] -= 1
            if pending["n"] <= 0:
                self._review(inc)
                self._toast("Noted: these will no longer be reported")

        for exe in inc["exes"]:
            run_sync_async("sensors.py", ["--allow", exe], one_done, timeout=30.0)


class InvestigatePage(Gtk.Box):
    """Incidents (stories) and Timeline (every event) behind one tab."""

    def __init__(self, toast_overlay: Adw.ToastOverlay) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        for side in ("top", "bottom", "start", "end"):
            getattr(self, f"set_margin_{side}")(24)
        self.append(page_header("Incidents", "Watches for attacks as they happen and explains what it sees. Observation only: nothing is stopped or changed.",
                                "dialog-warning-symbolic"))
        switch = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        switch.add_css_class("linked")
        self.append(switch)
        self.inc_btn = Gtk.ToggleButton(label="Incidents", active=True)
        self.tl_btn = Gtk.ToggleButton(label="All events (timeline)")
        self.tl_btn.set_group(self.inc_btn)
        self.cov_btn = Gtk.ToggleButton(label="What it can notice")
        self.cov_btn.set_group(self.inc_btn)
        switch.append(self.inc_btn)
        switch.append(self.tl_btn)
        switch.append(self.cov_btn)
        self.stack = Gtk.Stack(vexpand=True)
        self.append(self.stack)
        self.append(copy_action("Copy All Page Details", lambda: widget_report(self, "Security incidents")))

        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.incidents = IncidentsView(toast_overlay)
        scroller.set_child(self.incidents)
        self.stack.add_named(scroller, "incidents")
        self.timeline = TimelinePage(toast_overlay)
        for side in ("top", "bottom", "start", "end"):                 # the embedded timeline brings its own page margins
            getattr(self.timeline, f"set_margin_{side}")(0)
        self.stack.add_named(self.timeline, "timeline")
        cov_scroller = Gtk.ScrolledWindow(vexpand=True)
        cov_scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.coverage = CoverageView()
        cov_scroller.set_child(self.coverage)
        self.stack.add_named(cov_scroller, "coverage")
        self.cov_btn.connect("toggled", lambda b: b.get_active() and (self.coverage.refresh(), self.stack.set_visible_child_name("coverage")))
        self.inc_btn.connect("toggled", lambda b: b.get_active() and self.stack.set_visible_child_name("incidents"))
        self.tl_btn.connect("toggled", lambda b: b.get_active() and self.stack.set_visible_child_name("timeline"))

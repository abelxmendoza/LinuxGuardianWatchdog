"""Timeline page: everything LinuxGuardian has seen on this machine, newest first.

Read-only. Repeats are folded into one entry ("seen 87 times since Sep 4"), and "Mark as seen"
only hides an entry until the same finding shows up again; nothing is ever deleted.
"""
from __future__ import annotations

from datetime import datetime

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk, Pango  # noqa: E402

from linuxguardian_ui import scan_history  # noqa: E402,F401  (puts the suite dir on sys.path)
from linuxguardian_ui.components import page_header, section_header  # noqa: E402
from linuxguardian_ui.dialogs import confirm  # noqa: E402

import audit_events as ae  # noqa: E402
import notify_events as ne  # noqa: E402
import timeline as tl  # noqa: E402

SEV_LABEL = {"critical": "Critical", "warning": "Warning", "info": "Routine"}
KIND_LABEL = {"incident": "Possible incident", "finding": "Finding", "information": "Routine"}
SEV_CSS = {"critical": "omega-critical", "warning": "omega-warning", "info": "omega-dim"}
CATEGORY_LABEL = {
    "audit": "Security audit", "network": "Network exposure", "malware": "Malware scan",
    "rootkit": "Rootkit check", "integrity": "File integrity", "honeypot": "Honeypot",
    "process": "Processes", "maintenance": "Maintenance", "updates": "Updates",
}
SEVERITY_FILTERS = [("All activity", "info"), ("Warnings and critical", "warning"), ("Critical only", "critical")]


def day_heading(ts: float, now: float | None = None) -> str:
    import time

    now = time.time() if now is None else now
    delta = (datetime.fromtimestamp(now).date() - datetime.fromtimestamp(ts).date()).days
    if delta == 0:
        return "Today"
    if delta == 1:
        return "Yesterday"
    return datetime.fromtimestamp(ts).strftime("%A, %b %d").replace(" 0", " ")


class TimelinePage(Gtk.Box):
    def __init__(self, toast_overlay: Adw.ToastOverlay) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self._toast_overlay = toast_overlay
        for side in ("top", "bottom", "start", "end"):
            getattr(self, f"set_margin_{side}")(24)

        self.append(page_header("Timeline", "What LinuxGuardian has seen on this laptop. Repeats are folded together; nothing is deleted.",
                                "document-open-recent-symbolic"))
        self.summary = Gtk.Label(label="", xalign=0, wrap=True)
        self.append(self.summary)

        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        bar.add_css_class("process-toolbar")
        self.append(bar)
        self.severity = Gtk.DropDown.new_from_strings([label for label, _ in SEVERITY_FILTERS])
        self.severity.set_selected(1)
        self.severity.connect("notify::selected", lambda *_: self.refresh())
        bar.append(self.severity)
        self._categories: list[str] = []
        self.category = Gtk.DropDown.new_from_strings(["All areas"])
        self.category.connect("notify::selected", lambda *_: self.refresh(rebuild_categories=False))
        bar.append(self.category)
        self.search = Gtk.SearchEntry(placeholder_text="Search findings…", hexpand=True)
        self.search.connect("search-changed", lambda *_: self.refresh(rebuild_categories=False))
        bar.append(self.search)
        self.show_seen = Gtk.CheckButton(label="Show ones marked as seen")
        self.show_seen.connect("toggled", lambda *_: self.refresh(rebuild_categories=False))
        bar.append(self.show_seen)
        refresh = Gtk.Button(label="Refresh")
        refresh.connect("clicked", lambda _b: self.refresh())
        bar.append(refresh)

        notify_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.append(notify_row)
        self.notify_switch = Gtk.Switch(active=ne.is_enabled(), valign=Gtk.Align.CENTER)
        self.notify_switch.connect("notify::active", self._on_notify_toggled)
        notify_row.append(self.notify_switch)
        notify_row.append(Gtk.Label(label="Desktop notifications for possible incidents (and critical findings), never routine activity", xalign=0, hexpand=True))
        test = Gtk.Button(label="Send test")
        test.connect("clicked", self._on_test_notification)
        notify_row.append(test)

        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.append(scroller)
        self.list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        scroller.set_child(self.list_box)
        self._building = False
        self.refresh()

    # ---- data ---------------------------------------------------------------
    def refresh(self, rebuild_categories: bool = True) -> None:
        if self._building:
            return
        self._building = True
        try:
            entries = tl.load_entries()
            if rebuild_categories:
                self._set_categories(sorted({e.category for e in entries}))
            cat_index = self.category.get_selected()
            category = self._categories[cat_index - 1] if 0 < cat_index <= len(self._categories) else None
            min_sev = SEVERITY_FILTERS[self.severity.get_selected()][1]
            shown = tl.select(
                entries, min_severity=min_sev, category=category, search=self.search.get_text(),
                include_acknowledged=self.show_seen.get_active(),
            )
            self._render_summary(tl.select(entries))
            self._render(shown)
        finally:
            self._building = False

    def _set_categories(self, categories: list[str]) -> None:
        self._categories = categories
        model = Gtk.StringList.new(["All areas"] + [CATEGORY_LABEL.get(c, c.title()) for c in categories])
        self.category.set_model(model)
        self.category.set_selected(0)

    def _render_summary(self, active: list[tl.Entry]) -> None:
        counts = tl.summarize(active)
        open_ = [e for e in active if e.status != "resolved" and e.severity != "info"]
        incidents = sum(1 for e in open_ if e.kind == "incident")
        findings = len(open_) - incidents
        if counts["critical"]:
            text = f"{counts['critical']} critical and {counts['warning']} warning item(s) need a look"
        elif counts["warning"]:
            text = f"{counts['warning']} warning item{'s' if counts['warning'] != 1 else ''} to review. Nothing critical"
        else:
            text = "Nothing needs attention right now."
        if open_:
            text += f" ({incidents} possible incident{'s' if incidents != 1 else ''}, {findings} standing finding{'s' if findings != 1 else ''})."
        self.summary.set_label(text)
        for css in ("omega-critical", "omega-warning", "omega-heading"):
            self.summary.remove_css_class(css)
        self.summary.add_css_class("omega-critical" if counts["critical"] else "omega-warning" if counts["warning"] else "omega-heading")

    # ---- view ---------------------------------------------------------------
    def _clear(self) -> None:
        child = self.list_box.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.list_box.remove(child)
            child = nxt

    def _render(self, entries: list[tl.Entry]) -> None:
        self._clear()
        if not entries:
            empty = Gtk.Label(label="Nothing matches these filters.", xalign=0, margin_top=12)
            empty.add_css_class("omega-dim")
            self.list_box.append(empty)
            return
        current_day = None
        for entry in entries:
            heading = day_heading(entry.last_ts)
            if heading != current_day:
                current_day = heading
                self.list_box.append(section_header(heading))
            self.list_box.append(self._card(entry))

    def _card(self, entry: tl.Entry) -> Gtk.Widget:
        card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        card.add_css_class("omega-card")
        chip = Gtk.Label(label=SEV_LABEL[entry.severity] if entry.status != "resolved" else "Resolved", valign=Gtk.Align.START)
        chip.add_css_class("impact-badge")
        chip.add_css_class("omega-heading" if entry.status == "resolved" else SEV_CSS[entry.severity])
        card.append(chip)

        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3, hexpand=True)
        card.append(text)
        message = Gtk.Label(label=entry.message, xalign=0, wrap=True, selectable=True, max_width_chars=80)
        message.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        text.append(message)
        bits = [KIND_LABEL.get(entry.kind, entry.kind.title()), CATEGORY_LABEL.get(entry.category, entry.category.title()),
                f"last seen {tl.fmt_when(entry.last_ts)}"]
        if entry.count > 1:
            bits.append(f"seen {entry.count} times since {tl.fmt_when(entry.first_ts)}")
        detail = Gtk.Label(label=" · ".join(bits), xalign=0, wrap=True)
        detail.add_css_class("omega-dim")
        text.append(detail)

        accepted = entry.category == "audit" and ae.is_accepted(entry.message)
        if accepted:
            chip.set_label("Accepted")
            btn = Gtk.Button(label="Stop accepting", valign=Gtk.Align.CENTER)
            btn.set_tooltip_text("You'll be told about this finding again if it is still true.")
            btn.connect("clicked", self._on_unaccept, entry)
            card.append(btn)
        elif entry.category == "audit" and entry.status != "resolved" and entry.severity != "info":
            btn = Gtk.Button(label="Accept this risk", valign=Gtk.Align.CENTER)
            btn.set_tooltip_text("For something you've decided to live with. It stays visible here but stops being announced or counted against the rating.")
            btn.connect("clicked", self._on_accept, entry)
            card.append(btn)
        if entry.status != "resolved" and not accepted:
            btn = Gtk.Button(label="Unmark seen" if entry.acknowledged else "Mark as seen", valign=Gtk.Align.CENTER)
            btn.set_tooltip_text("Hides this until the same finding is seen again. Nothing is deleted.")
            btn.connect("clicked", self._on_toggle_seen, entry)
            card.append(btn)
        return card

    def _on_accept(self, _btn: Gtk.Button, entry: tl.Entry) -> None:
        confirm(self.get_root(), "Accept this risk?",
                f"{entry.message}\n\nIt stays visible in the Timeline, but you won't be notified about it again and it stops counting against the security "
                "rating. A different problem, or a possible attack, is never hidden by this. You can undo it at any time.", "Accept this risk",
                lambda: self._do_accept(entry), destructive=False)

    def _do_accept(self, entry: tl.Entry) -> None:
        ae.accept(entry.message)
        tl.acknowledge(entry.key)
        self.refresh(rebuild_categories=False)

    def _on_unaccept(self, _btn: Gtk.Button, entry: tl.Entry) -> None:
        ae.unaccept(entry.message)
        tl.unacknowledge(entry.key)
        self.refresh(rebuild_categories=False)

    def _on_toggle_seen(self, _btn: Gtk.Button, entry: tl.Entry) -> None:
        if entry.acknowledged:
            tl.unacknowledge(entry.key)
        else:
            tl.acknowledge(entry.key)
        self.refresh(rebuild_categories=False)

    def _on_notify_toggled(self, switch: Gtk.Switch, _pspec: object) -> None:
        ne.set_enabled(switch.get_active())

    def _on_test_notification(self, _btn: Gtk.Button) -> None:
        ok = ne.send_notification("LinuxGuardian: test", "Notifications are working. New security findings will show up here.")
        self._toast_overlay.add_toast(Adw.Toast.new("Test notification sent" if ok else "Could not send: is a notification service running?"))

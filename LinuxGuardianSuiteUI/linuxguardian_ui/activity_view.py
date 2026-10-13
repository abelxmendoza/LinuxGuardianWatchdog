"""GTK renderer for `activity.Activity`: a verdict banner and one card per step, instead of terminal output."""
from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Pango  # noqa: E402

from linuxguardian_ui.components import copy_action
from linuxguardian_ui.reports import export_card, audit_topic
from linuxguardian_ui.activity import Activity, Card, Group  # noqa: E402

SYMBOL = {"ok": "✓", "warn": "⚠", "fail": "✗", "info": "•", "running": "…"}
LABEL = {"ok": "Good", "warn": "Review", "fail": "Needs attention", "info": "Note", "running": "Working"}
MAX_LISTED = 120


def _label(text: str, css: str | None = None, *, selectable: bool = False, mono: bool = False) -> Gtk.Label:
    label = Gtk.Label(label=text, xalign=0, wrap=True, selectable=selectable)
    label.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
    if css:
        label.add_css_class(css)
    if mono:
        label.add_css_class("update-raw")
    return label


class ActivityView(Gtk.Box):
    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self._expanded: dict[str, bool] = {}
        self.on_action = None          # optional callback(name) for buttons inside cards (e.g. "review_baseline")
        self.empty_text = "Nothing has run yet. Use a button above to start."
        self.render(None)

    def clear(self) -> None:
        child = self.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.remove(child)
            child = nxt

    def render(self, activity: Activity | None) -> None:
        self.clear()
        if activity is None or not activity.cards():
            self.append(_label(self.empty_text if activity is None else "Starting…", "omega-dim"))
            return
        level, text = activity.headline()
        done = activity.exit_code is not None
        banner = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        banner.add_css_class("activity-banner")
        banner.add_css_class(f"activity-{level}")
        sym = Gtk.Label(label=SYMBOL.get(level, "•") if done else "…")
        sym.add_css_class("title-2")
        banner.append(sym)
        banner.append(_label(text, "activity-headline"))
        self.append(banner)
        self.append(copy_action("Copy All Findings", lambda: "\n".join(export_card(c) for c in activity.cards())))
        for card in activity.cards():
            self.append(self._card(card))

    # ------------------------------------------------------------------- cards
    def _card(self, c: Card) -> Gtk.Widget:
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        outer.add_css_class("activity-card")
        outer.add_css_class(f"activity-{c.status}")
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        outer.append(head)
        title = Gtk.Label(label=c.title, xalign=0, hexpand=True)
        title.add_css_class("activity-title")
        head.append(title)
        chip = Gtk.Label(label=LABEL.get(c.status, c.status))
        chip.add_css_class("activity-chip")
        chip.add_css_class(f"activity-chip-{c.status}")
        head.append(chip)
        head.append(copy_action("Copy Details", lambda: export_card(c)))
        if c.summary:
            outer.append(_label(c.summary))
        rows = sorted(c.rows, key=lambda row: audit_topic(row.text)[0]) if c.key == "audit" else c.rows
        last_topic = None
        for row in rows:
            if c.key == "audit":
                topic, explanation = audit_topic(row.text)
                if topic != last_topic:
                    outer.append(_label(topic, "activity-group-title"))
                    outer.append(_label(explanation, "omega-dim"))
                    last_topic = topic
            line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            mark = Gtk.Label(label=SYMBOL.get(row.kind, "•"), valign=Gtk.Align.START)
            mark.add_css_class(f"activity-mark-{row.kind}")
            line.append(mark)
            col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0, hexpand=True)
            col.append(_label(row.text, "omega-dim" if row.kind == "info" else None))
            if row.detail:
                col.append(_label(row.detail, "omega-dim"))
            line.append(col)
            outer.append(line)
        for g in c.groups:
            outer.append(self._group(c.key, g))
        return outer

    def _group(self, card_key: str, g: Group) -> Gtk.Widget:
        key = f"{card_key}/{g.key}"
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        mark = Gtk.Label(label=SYMBOL.get(g.level, "•"))
        mark.add_css_class(f"activity-mark-{g.level}")
        head.append(mark)
        t = Gtk.Label(label=g.title, xalign=0)
        t.add_css_class("activity-group-title")
        head.append(t)
        ex = Gtk.Expander()
        ex.set_label_widget(head)
        ex.set_expanded(self._expanded.get(key, g.level == "fail"))
        ex.connect("notify::expanded", lambda e, _p, k=key: self._expanded.__setitem__(k, e.get_expanded()))
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin_top=4, margin_start=24)
        if g.explanation:
            inner.append(_label(g.explanation, "omega-dim"))
        if g.extra:
            for title, why in g.extra:
                item = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
                item.append(_label(title, "update-name"))
                item.append(_label(why, "omega-dim"))
                inner.append(item)
        else:
            shown = g.items[:MAX_LISTED]
            text = "\n".join(shown) + (f"\n…and {len(g.items) - len(shown)} more" if len(g.items) > len(shown) else "")
            inner.append(_label(text, selectable=True, mono=True))
        if g.key == "changed_files" and self.on_action is not None:
            import gi as _gi  # noqa: F401

            btn = Gtk.Button(label="Review rootkit baseline…", halign=Gtk.Align.START)
            btn.connect("clicked", lambda _b: self.on_action("review_baseline"))
            inner.append(btn)
        ex.set_child(inner)
        return ex

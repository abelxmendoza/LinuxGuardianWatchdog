"""What LinuxGuardian can and can't notice: the attack coverage map, in plain words.

Honest by design: techniques nothing here would notice are listed as plainly as the ones that are covered, with what would help.
"""
from __future__ import annotations

import json

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Pango  # noqa: E402

from linuxguardian_ui import scan_history  # noqa: E402,F401  (puts the suite dir on sys.path)
from linuxguardian_ui.scripts import run_sync_async  # noqa: E402

STATUS = {"covered": ("Covered", "omega-heading"), "partial": ("Partly", "omega-warning"), "off": ("Turned off", "omega-warning"), "none": ("Not covered", "omega-critical")}


def _label(text: str, css: str | None = None, *, mono: bool = False) -> Gtk.Label:
    label = Gtk.Label(label=text, xalign=0, wrap=True)
    label.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
    if css:
        label.add_css_class(css)
    if mono:
        label.add_css_class("update-raw")
    return label


def _clear(box: Gtk.Box) -> None:
    child = box.get_first_child()
    while child is not None:
        nxt = child.get_next_sibling()
        box.remove(child)
        child = nxt


class CoverageView(Gtk.Box):
    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.summary = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.summary.add_css_class("omega-card")
        self.append(self.summary)
        self.body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.append(self.body)

    def refresh(self) -> None:
        run_sync_async("attack_coverage.py", ["--json"], self._got, timeout=30.0)

    def _got(self, code: int, lines: list[str]) -> None:
        try:
            s = json.loads("".join(lines))
        except ValueError:
            _clear(self.summary)
            self.summary.append(_label("Couldn't build the coverage map: " + (lines[-1] if lines else ""), "omega-critical"))
            return
        _clear(self.summary)
        _clear(self.body)
        c = s["counts"]
        self.summary.append(_label(f"{s['total']} common ways a laptop gets attacked: {c['covered']} covered, {c['partial']} partly, "
                                   f"{c['off']} covered but turned off, {c['none']} not covered.", "update-name"))
        self.summary.append(_label("No tool can check for every possible attack, and one that claimed to would give false confidence. This is the honest list, "
                                   "using MITRE ATT&CK names (the industry's shared vocabulary), including what is NOT noticed and what would help.", "omega-dim"))
        if s["next_gaps"]:
            self.summary.append(_label("Biggest gaps to close next:", "heading"))
            for g in s["next_gaps"][:5]:
                self.summary.append(_label(f"•  {g['name']} ({g['id']}): {g['gap']}", "omega-dim"))
        for tactic in s["tactics"]:
            rows = [r for r in s["rows"] if r["tactic"] == tactic]
            if not rows:
                continue
            h = _label(tactic, "heading")
            h.set_margin_top(6)
            self.body.append(h)
            for r in rows:
                self.body.append(self._row(r))

    def _row(self, r: dict) -> Gtk.Widget:
        word, css = STATUS[r["effective"]]
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        box.add_css_class("omega-card")
        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        top.append(_label(f"{r['name']}  ·  {r['id']}", "update-name"))
        top.get_first_child().set_hexpand(True)
        top.append(_label(word, css))
        box.append(top)
        box.append(_label(r["plain"], "omega-dim"))
        box.append(_label(r["by"]))
        if r["off"]:
            box.append(_label("Not active yet: " + "; ".join(r["off_text"]) + ".", "omega-warning"))
        if r["gap"]:
            box.append(_label("Missing: " + r["gap"], "omega-dim"))
        return box

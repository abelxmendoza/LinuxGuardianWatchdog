"""App health: is LinuxGuardian itself intact, private, and still watching?  Repairs are previewed and need your click."""
from __future__ import annotations

import json

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk, Pango  # noqa: E402

from linuxguardian_ui import scan_history  # noqa: E402,F401  (puts the suite dir on sys.path)
from linuxguardian_ui.dialogs import confirm  # noqa: E402
from linuxguardian_ui.scripts import run_sync_async  # noqa: E402

LEVEL = {"ok": ("✓", "omega-heading", None), "info": ("i", "omega-dim", None), "warning": ("!", "omega-warning", "activity-warn"),
         "critical": ("✕", "omega-critical", "activity-fail")}


def _label(text: str, css: str | None = None, *, selectable: bool = False, mono: bool = False) -> Gtk.Label:
    label = Gtk.Label(label=text, xalign=0, wrap=True, selectable=selectable)
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


def _parse(lines: list[str]) -> dict:
    try:
        return json.loads("".join(lines))
    except ValueError:
        return {"error": (lines[-1] if lines else "No answer.").removeprefix("[error]").strip()}


class HealthWindow(Gtk.Window):
    def __init__(self, parent: Gtk.Window | None, toast_overlay: Adw.ToastOverlay | None = None, on_result=None, open_terminal=None) -> None:
        super().__init__(transient_for=parent, modal=False, title="LinuxGuardian health")
        self.set_default_size(700, 720)
        self._toast_overlay, self._on_result, self._open_terminal = toast_overlay, on_result, open_terminal
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.set_child(scroller)
        self.body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=18, margin_bottom=18, margin_start=18, margin_end=18)
        scroller.set_child(self.body)
        head = _label("Is LinuxGuardian itself healthy?", "omega-heading")
        head.add_css_class("title-3")
        self.body.append(head)
        self.body.append(_label("A security tool is a target, so it checks itself: that its own files haven't been changed, that other users can't tamper with "
                                "or read its data, that its saved state is intact, and that live monitoring is really running. Repairs are previewed first.", "omega-dim"))
        self.banner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.body.append(self.banner)
        self.cards = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.body.append(self.cards)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, halign=Gtk.Align.START)
        self.body.append(row)
        again = Gtk.Button(label="Check again")
        again.connect("clicked", lambda _b: self.refresh())
        row.append(again)
        if open_terminal:
            term = Gtk.Button(label="Run this check in a terminal")
            term.connect("clicked", lambda _b: open_terminal("self_check"))
            row.append(term)
        self.body.append(_label("Honest limit: someone who already controls your account can change the app and its baseline too. This catches accidents, "
                                "half-finished updates and unsophisticated tampering, and raises an alert; it can't promise more.", "omega-dim"))
        self.refresh()

    def _toast(self, text: str) -> None:
        if self._toast_overlay is not None:
            self._toast_overlay.add_toast(Adw.Toast.new(text))

    def refresh(self) -> None:
        _clear(self.banner)
        self.banner.append(_label("Checking…", "omega-dim"))
        run_sync_async("self_check.py", ["--check", "--json"], self._got, timeout=60.0)

    def _got(self, code: int, lines: list[str]) -> None:
        r = _parse(lines)
        _clear(self.banner)
        _clear(self.cards)
        if r.get("error"):
            self.banner.append(_label("The health check couldn't run: " + r["error"], "omega-critical"))
            return
        if self._on_result:
            self._on_result(r)
        banner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        banner.add_css_class("activity-banner")
        banner.add_css_class({"critical": "activity-fail", "warning": "activity-warn"}.get(r["level"], "activity-ok"))
        banner.append(_label(r["headline"], "activity-headline"))
        self.banner.append(banner)
        for c in r["checks"]:
            mark, css, _card = LEVEL[c["level"]]
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            card.add_css_class("omega-card")
            top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            top.append(_label(f"{mark}  {c['title']}", css))
            top.get_first_child().set_hexpand(True)
            card.append(top)
            card.append(_label(c["text"]))
            if c["detail"]:
                ex = Gtk.Expander(label=f"Details ({len(c['detail'])})")
                ex.set_child(_label("\n".join(c["detail"]), "omega-dim", selectable=True, mono=True))
                card.append(ex)
            repairs = c.get("repairs") or ([c["repair"]] if c.get("repair") else [])
            for rep in repairs:
                btn = Gtk.Button(label=self._repair_label(rep), halign=Gtk.Align.START)
                btn.add_css_class("suggested-action" if c["level"] != "info" else "flat")
                btn.connect("clicked", lambda _b, x=rep: self._preview(x))
                card.append(btn)
            self.cards.append(card)

    @staticmethod
    def _repair_label(rep: str) -> str:
        return {"perms": "Make my data folder private…", "app_perms": "Stop others from writing to the app…", "accept": "I made this change: accept it…"}.get(
            rep, "Repair this file…")

    def _preview(self, repair: str) -> None:
        def got(code: int, lines: list[str]) -> None:
            p = _parse(lines)
            if p.get("error"):
                self._toast(p["error"])
                return
            body = "\n".join(f"•  {s}" for s in p["steps"][:12]) + f"\n\n{p['note']}"
            confirm(self, p["title"] + "?", body, "Do it", lambda: self._apply(repair), destructive=False)

        run_sync_async("self_check.py", ["--plan", repair, "--json"], got, timeout=30.0)

    def _apply(self, repair: str) -> None:
        def done(code: int, lines: list[str]) -> None:
            self._toast((lines[-1] if lines else "Done").removeprefix("[error]").strip())
            self.refresh()

        run_sync_async("self_check.py", ["--apply", repair], done, timeout=60.0)

"""Terminal commands: every feature as a command you can copy or open in a terminal, for when the app itself misbehaves.

Each entry has the app's own command and a "plain tools" command that works even if LinuxGuardian is broken. What opens is always
text from a fixed list; the only values filled in are a process id or an incident id that you type, and those are validated.
"""
from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk, Pango  # noqa: E402

from linuxguardian_ui import scan_history  # noqa: E402,F401  (puts the suite dir on sys.path)
from linuxguardian_ui.clipboard import copy_text  # noqa: E402
from linuxguardian_ui.dialogs import confirm  # noqa: E402

import fallback  # noqa: E402


def _label(text: str, css: str | None = None, *, selectable: bool = False, mono: bool = False) -> Gtk.Label:
    label = Gtk.Label(label=text, xalign=0, wrap=True, selectable=selectable)
    label.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
    if css:
        label.add_css_class(css)
    if mono:
        label.add_css_class("update-raw")
    return label


class TerminalWindow(Gtk.Window):
    def __init__(self, parent: Gtk.Window | None, toast_overlay: Adw.ToastOverlay | None = None, focus: str | None = None) -> None:
        super().__init__(transient_for=parent, modal=False, title="Terminal commands")
        self.set_default_size(820, 760)
        self._toast_overlay = toast_overlay
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self.set_child(root)
        head = _label("Terminal commands", "omega-heading")
        head.add_css_class("title-3")
        root.append(head)
        root.append(_label("If a button misbehaves, or the app won't open, every feature can still be run by hand. Each one has the app's own command and a "
                           "\"without the app\" version made only of standard Linux tools. Open it in a terminal, or copy it.", "omega-dim"))
        self.search = Gtk.SearchEntry(placeholder_text="Search: scan, firewall, updates, logins…")
        self.search.connect("search-changed", lambda *_: self._filter())
        root.append(self.search)
        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        root.append(scroller)
        self.list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        scroller.set_child(self.list)
        self.status = _label("", "omega-dim")
        root.append(self.status)
        self._cards: list[tuple[Gtk.Widget, str, bool]] = []
        self._build()
        if focus:
            self.search.set_text(focus)

    def _toast(self, text: str) -> None:
        self.status.set_label(text)
        if self._toast_overlay is not None:
            self._toast_overlay.add_toast(Adw.Toast.new(text))

    def _build(self) -> None:
        group = None
        for row in fallback.listing():
            if row["group"] != group:
                group = row["group"]
                h = _label(group, "heading")
                h.set_margin_top(8)
                self.list.append(h)
                self._cards.append((h, "", True))
            card = self._card(row)
            self.list.append(card)
            self._cards.append((card, f"{row['group']} {row['title']} {row['what']} {row['id']} {row['app_command'] or ''} {row['plain_command'] or ''}".lower(), False))

    def _card(self, row: dict) -> Gtk.Widget:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card.add_css_class("omega-card")
        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        top.append(_label(row["title"], "update-name"))
        top.get_first_child().set_hexpand(True)
        if row["safety"] == fallback.CHANGE:
            tag = _label("changes things", "omega-warning")
            top.append(tag)
        if row["password"] or row["plain_password"]:
            top.append(_label("asks for your password", "omega-dim"))
        card.append(top)
        card.append(_label(row["what"], "omega-dim"))
        entry = None
        if row["needs_param"]:
            hint = "process id (a number)" if row["needs_param"] == "pid" else "incident id (from the Incidents tab)"
            entry = Gtk.Entry(placeholder_text=hint)
            card.append(entry)
        buttons: list[Gtk.Button] = []
        for which, label, cmd in (("app", "With the app", row["app_command"]), ("plain", "Without the app (plain Linux tools)", row["plain_command"])):
            if not cmd:
                continue
            card.append(_label(label, "omega-dim"))
            code = _label(cmd, selectable=True, mono=True)
            card.append(code)
            line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            cp = Gtk.Button(label="Copy")
            op = Gtk.Button(label="Open in terminal")
            op.add_css_class("suggested-action")
            line.append(cp)
            line.append(op)
            card.append(line)
            buttons += [cp, op]
            cp.connect("clicked", lambda _b, r=row, w=which, e=entry, c=code: self._copy(r, w, e, c))
            op.connect("clicked", lambda _b, r=row, w=which, e=entry: self._open(r, w, e))
        if row["why_plain"]:
            card.append(_label(row["why_plain"], "omega-dim"))
        if entry is not None:
            def validate(*_a, e=entry, bs=buttons, spec=row["needs_param"]) -> None:
                ok = bool(fallback.PARAMS[spec].fullmatch(e.get_text().strip()))
                for b in bs:
                    b.set_sensitive(ok)
                e.remove_css_class("error") if ok or not e.get_text() else e.add_css_class("error")

            entry.connect("changed", validate)
            validate()
        return card

    def _resolved(self, row: dict, which: str, entry: Gtk.Entry | None) -> str | None:
        try:
            c = fallback.commands(row["id"], entry.get_text().strip() if entry is not None else None)
        except fallback.FallbackError as exc:
            self._toast(str(exc))
            return None
        return c["app_command"] if which == "app" else c["plain_command"]

    def _copy(self, row: dict, which: str, entry: Gtk.Entry | None, code: Gtk.Label) -> None:
        cmd = self._resolved(row, which, entry)
        if cmd:
            copy_text(cmd)
            self._toast("Command copied. Paste it into a terminal.")

    def _open(self, row: dict, which: str, entry: Gtk.Entry | None) -> None:
        param = entry.get_text().strip() if entry is not None else None

        def go() -> None:
            ok, msg = fallback.open_in_terminal(row["id"], which, param)
            self._toast(msg)

        if row["safety"] == fallback.CHANGE:
            confirm(self, f"{row['title']}?", "This changes something on your computer. It opens in a terminal where you can see exactly what it does, "
                    "and some of these ask for your password there.", "Open in terminal", go, destructive=False)
        else:
            go()

    def _filter(self) -> None:
        q = self.search.get_text().strip().lower()
        heading, shown = None, False
        for widget, text, is_group in self._cards:
            if is_group:
                if heading is not None:
                    heading.set_visible(shown or not q)
                heading, shown = widget, False
            else:
                vis = not q or q in text
                widget.set_visible(vis)
                shown = shown or vis
        if heading is not None:
            heading.set_visible(shown or not q)

"""Hardening page: make this laptop harder to attack, one understandable step at a time.

Three parts: the hardening checklist (what's weak, why it matters, a previewed fix you can undo), VPN status
for Tailscale and Proton VPN together, and diagnostics (which features work and what's missing).
Nothing changes until you press a fix button and confirm what it will do.
"""
from __future__ import annotations

import json

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk, Pango  # noqa: E402

from linuxguardian_ui import scan_history  # noqa: E402,F401  (puts the suite dir on sys.path)
from linuxguardian_ui.clipboard import copy_text  # noqa: E402
from linuxguardian_ui.components import page_header, section_header  # noqa: E402
from linuxguardian_ui.dialogs import confirm  # noqa: E402
from linuxguardian_ui.scripts import run_streaming_async, run_sync_async  # noqa: E402

CHIP = {"attention": ("Fix", "omega-warning"), "ok": ("Good", "omega-heading"), "info": ("Note", "omega-dim"), "unknown": ("Unknown", "omega-dim")}
GROUP_ORDER = ["Access", "Network", "Secrets", "Disk & boot", "Defences", "Other"]


def _label(text: str, css: str | None = None, *, selectable: bool = False) -> Gtk.Label:
    label = Gtk.Label(label=text, xalign=0, wrap=True, selectable=selectable)
    label.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
    if css:
        label.add_css_class(css)
    return label


def bulk_candidates(checks: list[dict]) -> list[dict]:
    """Fixes safe to apply in one go: a problem with exactly ONE recommended, not-yet-applied remedy.
    Anything that needs a choice (Screen Sharing: off, or locked down?) is left for the person to decide."""
    out = []
    for c in checks:
        if c["state"] == "attention" and len(c["fixes"]) == 1 and c["fixes"][0]["recommended"] and not c["fixes"][0]["applied"]:
            out.append({**c["fixes"][0], "check_title": c["title"]})
    return out


class HardeningPage(Gtk.Box):
    def __init__(self, toast_overlay: Adw.ToastOverlay) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self._toast_overlay = toast_overlay
        self._checks: list[dict] = []
        self._busy = False
        for side in ("top", "bottom", "start", "end"):
            getattr(self, f"set_margin_{side}")(24)

        self.append(page_header("Hardening", "Make this laptop harder to attack, one safe step at a time. Nothing changes until you confirm.",
                                "security-high-symbolic"))
        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.append(scroller)
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        scroller.set_child(body)

        # ---- summary
        self.summary_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.summary_card.add_css_class("omega-card")
        body.append(self.summary_card)
        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        self.summary_card.append(top)
        self.percent = Gtk.Label(label="…", xalign=0)
        self.percent.add_css_class("title-1")
        self.percent.add_css_class("omega-heading")
        top.append(self.percent)
        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
        top.append(text)
        self.headline = _label("Checking your laptop…")
        self.headline.add_css_class("title-4")
        text.append(self.headline)
        self.subline = _label("", "omega-dim")
        text.append(self.subline)
        self.bar = Gtk.ProgressBar(hexpand=True)
        self.summary_card.append(self.bar)
        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.summary_card.append(buttons)
        self.bulk_btn = Gtk.Button(label="Fix the recommended ones…")
        self.bulk_btn.add_css_class("suggested-action")
        self.bulk_btn.set_sensitive(False)
        self.bulk_btn.connect("clicked", self._on_bulk)
        buttons.append(self.bulk_btn)
        recheck = Gtk.Button(label="Check again")
        recheck.connect("clicked", lambda _b: self.refresh())
        buttons.append(recheck)
        self.spinner = Gtk.Spinner()
        buttons.append(self.spinner)

        self.checks_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        body.append(self.checks_box)

        # ---- VPN lives on its own tab now
        vpn_note = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        vpn_note.add_css_class("guardian-banner")
        vpn_note.append(_label("Tailscale and Proton VPN status has its own tab.", None))
        go = Gtk.Button(label="Open VPN tab")
        go.connect("clicked", self._open_vpn_tab)
        vpn_note.append(go)
        body.append(vpn_note)

        # ---- diagnostics
        body.append(section_header("Diagnostics: is everything working?"))
        self.diag_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.diag_card.add_css_class("omega-card")
        body.append(self.diag_card)
        self.diag_card.append(_label("Checks that the tools LinuxGuardian relies on are installed, that password prompts can appear, "
                                     "and that this install is intact. Shows which features are affected by anything missing.", "omega-dim"))
        drow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.diag_card.append(drow)
        self.diag_btn = Gtk.Button(label="Run diagnostics")
        self.diag_btn.connect("clicked", lambda _b: self.run_diagnostics())
        drow.append(self.diag_btn)
        self.diag_copy = Gtk.Button(label="Copy report")
        self.diag_copy.set_sensitive(False)
        self.diag_copy.connect("clicked", self._copy_diag)
        drow.append(self.diag_copy)
        self.diag_out = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.diag_card.append(self.diag_out)
        self._diag_text = ""

        self.refresh()

    # ---- helpers --------------------------------------------------------------
    def _toast(self, text: str) -> None:
        self._toast_overlay.add_toast(Adw.Toast.new(text))

    @staticmethod
    def _clear(box: Gtk.Box) -> None:
        child = box.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            box.remove(child)
            child = nxt

    def _chip(self, state: str) -> Gtk.Widget:
        text, css = CHIP[state]
        chip = Gtk.Label(label=text, valign=Gtk.Align.START)
        chip.add_css_class("impact-badge")
        chip.add_css_class(css)
        return chip

    # ---- checklist -------------------------------------------------------------
    def refresh(self) -> None:
        self.spinner.start()
        run_sync_async("hardening.py", ["--check", "--json"], self._on_checks, timeout=60.0)

    def _on_checks(self, code: int, lines: list[str]) -> None:
        self.spinner.stop()
        try:
            data = json.loads("".join(lines))
        except json.JSONDecodeError:
            self.headline.set_label("Couldn't run the hardening checks.")
            self.subline.set_label(" ".join(lines)[:200])
            return
        self._checks = data["checks"]
        self._applied = data.get("applied", [])
        self._render(data["score"])

    def _render(self, score: dict) -> None:
        total = score["total"] or 1
        self.percent.set_label(f"{score['percent']}%")
        self.bar.set_fraction(score["ok"] / total)
        n = score["attention"]
        self.headline.set_label("Your laptop is in good shape." if n == 0 else f"{n} thing{'s' if n != 1 else ''} could be tightened.")
        self.subline.set_label(f"{score['ok']} of {score['total']} protections are in place.")
        for css in ("omega-heading", "omega-warning", "omega-critical"):
            self.percent.remove_css_class(css)
        self.percent.add_css_class("omega-heading" if score["percent"] >= 80 else "omega-warning")
        bulk = bulk_candidates(self._checks)
        self.bulk_btn.set_sensitive(bool(bulk) and not self._busy)
        self.bulk_btn.set_label(f"Fix the {len(bulk)} recommended…" if bulk else "Fix the recommended ones…")

        self._clear(self.checks_box)
        order = {"attention": 0, "info": 1, "unknown": 2, "ok": 3}
        needs = [c for c in self._checks if c["state"] == "attention"]
        rest = [c for c in self._checks if c["state"] != "attention"]
        if needs:
            self.checks_box.append(section_header("Needs your attention"))
            for c in sorted(needs, key=lambda c: GROUP_ORDER.index(c["group"]) if c["group"] in GROUP_ORDER else 99):
                self.checks_box.append(self._card(c))
        if getattr(self, "_applied", None):
            self.checks_box.append(section_header("Changes LinuxGuardian made (you can undo any of them)"))
            for a in self._applied:
                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
                row.add_css_class("omega-card")
                row.append(self._chip("ok"))
                row.append(Gtk.Label(label=a["label"], xalign=0, hexpand=True))
                undo = Gtk.Button(label="Undo", valign=Gtk.Align.CENTER)
                undo.connect("clicked", lambda _b, fx=a: self._confirm_fix(fx, undo=True))
                row.append(undo)
                self.checks_box.append(row)
        if rest:
            expander = Gtk.Expander(label=f"Already fine or for your information ({len(rest)})")
            inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_top=8)
            for c in sorted(rest, key=lambda c: (order[c["state"]], c["group"])):
                inner.append(self._card(c))
            expander.set_child(inner)
            self.checks_box.append(expander)

    def _card(self, c: dict) -> Gtk.Widget:
        card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        card.add_css_class("omega-card")
        card.append(self._chip(c["state"]))
        col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, hexpand=True)
        card.append(col)
        title = Gtk.Label(label=c["title"], xalign=0)
        title.add_css_class("update-name")
        col.append(title)
        col.append(_label(c["summary"]))
        if c["why"] and c["state"] != "ok":
            col.append(_label("Why it matters: " + c["why"], "omega-dim"))
        if c["detail"]:
            ex = Gtk.Expander(label="Technical details")
            d = _label(c["detail"], "update-raw", selectable=True)
            ex.set_child(d)
            col.append(ex)
        if c["advice"] and c["state"] != "ok":
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            row.append(_label("What to do: " + c["advice"], "omega-warning", selectable=True))
            col.append(row)
        fixes = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        for f in c["fixes"]:
            if f["applied"]:
                btn = Gtk.Button(label=f"Undo: {f['label']}")
                btn.connect("clicked", lambda _b, fx=f: self._confirm_fix(fx, undo=True))
            else:
                btn = Gtk.Button(label=f["label"])
                if f["recommended"]:
                    btn.add_css_class("suggested-action")
                btn.connect("clicked", lambda _b, fx=f: self._confirm_fix(fx, undo=False))
            fixes.append(btn)
        if c["fixes"]:
            col.append(fixes)
        return card

    # ---- applying fixes ---------------------------------------------------------
    def _effect_text(self, fx: dict) -> str:
        lines = "\n".join("•  " + e for e in fx["effect"])
        extra = f"\n\n{fx['caution']}" if fx.get("caution") else ""
        pw = "\n\nYour desktop will ask for your password." if fx["kind"] == "root" else ""
        return f"This will:\n{lines}{extra}{pw}\n\nYou can undo it afterwards."

    def _confirm_fix(self, fx: dict, undo: bool) -> None:
        if self._busy:
            return
        if undo:
            confirm(self.get_root(), f"Undo: {fx['label']}?", "This puts back what it replaced." +
                    ("\n\nYour desktop will ask for your password." if fx["kind"] == "root" else ""), "Undo",
                    lambda: self._run_fix(fx, "undo"), destructive=False)
        else:
            confirm(self.get_root(), fx["label"] + "?", self._effect_text(fx), "Do it", lambda: self._run_fix(fx, "apply"), destructive=False)

    def _run_fix(self, fx: dict, mode: str, then=None) -> None:
        self._busy = True
        self.spinner.start()
        flag = f"--{mode}"

        def finish(ok: bool, message: str) -> None:
            self._busy = False
            self.spinner.stop()
            self._toast(message)
            if then is not None and ok:
                then()
            else:
                self.refresh()

        if fx["kind"] == "root":
            collected: list[str] = []

            def on_done(code: int) -> bool:
                msg = {0: "Done", 2: "Cancelled: nothing was changed", 3: "Refused: nothing was changed"}.get(code, "That didn't work. See the log.")
                finish(code == 0, f"{fx['label']}: {msg}" if code == 0 else msg)
                return False

            run_streaming_async("linux_hardening.sh", [flag, fx["id"]], lambda line: (collected.append(line), False)[1], on_done)
        else:
            def done(code: int, lines: list[str]) -> None:
                finish(code == 0, (lines[-1] if lines else "Done") if code == 0 else (lines[-1] if lines else "That didn't work."))

            run_sync_async("hardening.py", [flag, fx["id"]], done, timeout=90.0)

    def _on_bulk(self, _btn: Gtk.Button) -> None:
        todo = bulk_candidates(self._checks)
        if not todo or self._busy:
            return
        needs_pw = [f["label"] for f in todo if f["kind"] == "root"]
        body = "These will be applied one after another:\n" + "\n".join("•  " + f["label"] for f in todo)
        if needs_pw:
            body += f"\n\n{len(needs_pw)} of them need your password (the desktop asks separately)."
        body += "\n\nEach one can be undone from this page. Choices that depend on how you use your laptop (like Screen Sharing) are not included."
        confirm(self.get_root(), f"Apply {len(todo)} recommended fixes?", body, "Apply", lambda: self._run_queue(list(todo)), destructive=False)

    def _run_queue(self, todo: list[dict]) -> None:
        if not todo:
            self._toast("All recommended fixes applied")
            self.refresh()
            return
        fx = todo.pop(0)
        self._run_fix(fx, "apply", then=lambda: self._run_queue(todo))

    def _open_vpn_tab(self, _btn: Gtk.Button) -> None:
        stack = getattr(self.get_root(), "view_stack", None)
        if stack is not None:
            stack.set_visible_child_name("vpn")

    # ---- diagnostics ---------------------------------------------------------------
    def run_diagnostics(self) -> None:
        self.diag_btn.set_sensitive(False)
        self._clear(self.diag_out)
        self.diag_out.append(_label("Running…", "omega-dim"))

        def done(code: int, lines: list[str]) -> None:
            self.diag_btn.set_sensitive(True)
            self._clear(self.diag_out)
            try:
                r = json.loads("".join(lines))
            except json.JSONDecodeError:
                self.diag_out.append(_label("Diagnostics couldn't run: " + " ".join(lines)[:200], "omega-warning"))
                return
            self._show_diag(r)

        run_sync_async("diagnostics.py", ["--json"], done, timeout=90.0)

    def _show_diag(self, r: dict) -> None:
        import diagnostics as dg

        self._diag_text = dg.render_text(r)
        self.diag_copy.set_sensitive(True)
        status = {"ready": ("Works", "omega-heading"), "limited": ("Limited", "omega-warning"), "unavailable": ("Not available", "omega-critical")}
        self.diag_out.append(_label("Everything is working." if r["healthy"] else "Some things need attention.", "omega-heading" if r["healthy"] else "omega-warning"))
        for f in r["features"]:
            text, css = status[f["status"]]
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            chip = Gtk.Label(label=text, valign=Gtk.Align.START)
            chip.add_css_class("impact-badge")
            chip.add_css_class(css)
            row.append(chip)
            col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1, hexpand=True)
            col.append(_label(f["feature"]))
            if f["missing"]:
                col.append(_label("Missing: " + ", ".join(f["missing"]) + ".  " + " ".join(f["hints"]), "omega-dim", selectable=True))
            row.append(col)
            self.diag_out.append(row)
        for e in r["environment"]:
            if e["state"] in ("problem", "note"):
                self.diag_out.append(_label(("Problem: " if e["state"] == "problem" else "Note: ") + e["title"] + ". " + e["detail"] + (" " + e["hint"] if e["hint"] else ""),
                                            "omega-warning" if e["state"] == "problem" else "omega-dim", selectable=True))
        s = r.get("scripts")
        if s and s["broken"]:
            self.diag_out.append(_label("Damaged or non-runnable files in this install: " + ", ".join(s["broken"]), "omega-critical"))
        if not r["gtk"]["ok"]:
            self.diag_out.append(_label(r["gtk"]["detail"], "omega-critical"))

    def _copy_diag(self, _btn: Gtk.Button) -> None:
        try:
            copy_text(self._diag_text)
            self._toast("Diagnostics report copied")
        except Exception as exc:  # noqa: BLE001
            self._toast(f"Copy failed: {exc}")

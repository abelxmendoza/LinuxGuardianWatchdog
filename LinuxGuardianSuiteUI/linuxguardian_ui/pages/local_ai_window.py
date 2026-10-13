"""Free local AI setup: get a private, no-cost model running and find out whether it is any good.

Everything here is a step the person takes on purpose. LinuxGuardian never runs the Ollama installer for you (it installs
software as root, so you read it and run it yourself); downloading a multi-gigabyte model needs a click and a confirmation;
and a model is only trusted after the quality check has graded it.
"""
from __future__ import annotations

import json

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gtk, Pango  # noqa: E402

from linuxguardian_ui import scan_history  # noqa: E402,F401  (puts the suite dir on sys.path)
from linuxguardian_ui.clipboard import copy_text  # noqa: E402
from linuxguardian_ui.dialogs import confirm  # noqa: E402
from linuxguardian_ui.scripts import run_streaming_async, run_sync_async  # noqa: E402

FIT_CSS = {"fits": "omega-heading", "tight": "omega-warning", "slow": "omega-warning", "too_big": "omega-critical"}
GRADE_CSS = {"Good": ("activity-ok", "omega-heading"), "Use with caution": ("activity-warn", "omega-warning"), "Not reliable": ("activity-fail", "omega-critical")}


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
    for line in reversed(lines):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                break
    try:
        return json.loads("".join(lines))
    except ValueError:
        return {"error": " ".join(lines)[-300:] or "No answer."}


def grade_summary(grade: dict | None) -> str:
    """One plain line for a model's quality-check state."""
    if not grade:
        return ""
    if grade["state"] == "ungraded":
        return "Not checked yet"
    pct = f" ({round((grade.get('score') or 0) * 100)}%)" if grade.get("score") is not None else ""
    return f"{grade.get('grade')}{pct}" + (", out of date: re-run the check" if grade["state"] == "stale" else "")


def grade_banner(grade: dict | None, open_setup=None) -> Gtk.Widget | None:
    """A banner telling the person how far to trust the local model behind an answer. None for cloud models."""
    if not grade:
        return None
    state, g = grade["state"], grade.get("grade")
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    box.add_css_class("activity-banner")
    if state == "ungraded" or state == "stale" or g in (None, "Not reliable", "Use with caution"):
        if state == "ungraded":
            box.add_css_class("activity-warn")
            box.append(_label(f"The local model '{grade['model']}' hasn't been quality-checked. Small models can sound sure and still be wrong about "
                              "security. Treat this answer as a hint, and run the quality check to see how far to trust it.", "activity-headline"))
        else:
            box.add_css_class(GRADE_CSS.get(g, ("activity-warn", ""))[0])
            stale = " (graded before the test changed; re-run to be sure)" if state == "stale" else ""
            box.append(_label(f"Local model quality check: {g}{stale}.", "activity-headline"))
            for r in grade.get("reasons", [])[:3]:
                box.append(_label("•  " + r))
            if g == "Not reliable":
                box.append(_label("Don't rely on its verdicts. Choose a different model, or use the sensors' own explanation above.", "omega-dim"))
        if open_setup:
            btn = Gtk.Button(label="Open local AI setup", halign=Gtk.Align.START)
            btn.connect("clicked", lambda _b: open_setup())
            box.append(btn)
        return box
    box.add_css_class("activity-ok")
    box.append(_label(f"Local model quality check: {g} ({round((grade.get('score') or 0) * 100)}%). Still verify before you act.", "omega-dim"))
    return box


class LocalAiWindow(Gtk.Window):
    def __init__(self, parent: Gtk.Window, toast_overlay: Adw.ToastOverlay | None, on_changed=None) -> None:
        super().__init__(transient_for=parent, modal=False, title="Free local AI setup")
        self.set_default_size(700, 760)
        self._toast_overlay, self._on_changed, self._status = toast_overlay, on_changed, {}
        self._cancel = None
        self._busy = False
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.set_child(scroller)
        self.body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14, margin_top=18, margin_bottom=18, margin_start=18, margin_end=18)
        scroller.set_child(self.body)
        head = _label("Free, private AI on this laptop", "omega-heading")
        head.add_css_class("title-3")
        self.body.append(head)
        self.body.append(_label("A model running on your own computer costs nothing and nothing you investigate ever leaves the machine. "
                                "Small models can be wrong about security, so the last step grades the one you pick on made-up attacks, harmless look-alikes "
                                "and attempts to trick it.", "omega-dim"))
        self.hw = _label("Looking at your hardware…", "omega-dim")
        self.body.append(self.hw)
        self.sections = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.body.append(self.sections)
        self.progress_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.body.append(self.progress_box)
        self.result_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.body.append(self.result_box)
        self.connect("close-request", self._on_close)
        self.refresh()

    # ---- plumbing --------------------------------------------------------------
    def _toast(self, text: str) -> None:
        if self._toast_overlay is not None:
            self._toast_overlay.add_toast(Adw.Toast.new(text))

    def _on_close(self, *_a) -> bool:
        if self._cancel:
            self._cancel()
        return False

    def refresh(self) -> None:
        run_sync_async("local_ai.py", ["--status", "--json"], self._got_status, timeout=30.0)

    def _got_status(self, code: int, lines: list[str]) -> None:
        self._status = _parse(lines)
        if self._status.get("error"):
            self.hw.set_label("Couldn't read the setup status: " + self._status["error"])
            return
        h = self._status["hardware"]
        gpu = f"{h['gpu']['name']} with {h['gpu']['vram_gb']} GB of graphics memory" if h.get("gpu") else "no NVIDIA graphics card found (models will run on the CPU, slowly)"
        self.hw.set_label(f"Your machine: {gpu}; {h.get('ram_gb') or '?'} GB RAM; {h.get('disk_free_gb') or '?'} GB free disk.")
        self._render()
        if self._on_changed:
            self._on_changed()

    # ---- sections ---------------------------------------------------------------
    def _section(self, number: int, title: str, state: str) -> Gtk.Box:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        card.add_css_class("omega-card")
        mark = {"done": "✓", "todo": "→", "wait": "○"}[state]
        h = _label(f"{mark}  {number}. {title}", "update-name" if state != "wait" else "omega-dim")
        card.append(h)
        self.sections.append(card)
        return card

    def _render(self) -> None:
        _clear(self.sections)
        s = self._status
        ol = s["ollama"]
        step = s["step"]

        # 1. Ollama
        c = self._section(1, "Ollama: the free program that runs models", "done" if ol["reachable"] else "todo")
        if ol["reachable"]:
            c.append(_label("Installed and running.", "omega-heading"))
        elif ol["installed"]:
            c.append(_label("Installed, but not running. Start it with one of these, then press Check again:", "omega-warning"))
            c.append(_label("sudo systemctl start ollama     (if installed as a service)\nollama serve     (to run it by hand in a terminal)", selectable=True, mono=True))
        else:
            c.append(_label("Not installed. This is the official one-line installer from ollama.com. LinuxGuardian will not run it for you, because it "
                            "installs software with administrator rights: open a terminal, paste it, and read what it does if you like.", "omega-dim"))
            c.append(_label(s["install_command"], selectable=True, mono=True))
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            c.append(row)
            cp = Gtk.Button(label="Copy command")
            cp.connect("clicked", lambda _b: (copy_text(self, s["install_command"]), self._toast("Command copied")))
            row.append(cp)
            op = Gtk.Button(label="Open the download page")
            op.connect("clicked", lambda _b: Gtk.show_uri(self, s["install_page"], Gdk.CURRENT_TIME))
            row.append(op)
        again = Gtk.Button(label="Check again", halign=Gtk.Align.START)
        again.connect("clicked", lambda _b: self.refresh())
        c.append(again)

        # 2. Download
        c = self._section(2, "Download a model", "done" if ol["models"] else ("todo" if ol["reachable"] else "wait"))
        c.append(_label("Each is a one-time download of a few gigabytes. Your 'fits' rating is based on the graphics memory found above.", "omega-dim"))
        for r in s["suggestions"]:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            c.append(row)
            info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1, hexpand=True)
            row.append(info)
            star = "  (suggested)" if r["tag"] == s.get("recommended") else ""
            info.append(_label(f"{r['title']}  ·  {r['tag']}  ·  about {r['gb']} GB{star}", "update-name"))
            info.append(_label(r["note"], "omega-dim"))
            info.append(_label(r["fit"]["text"], FIT_CSS.get(r["fit"]["level"])))
            btn = Gtk.Button(label="Downloaded" if r["installed"] else "Download")
            btn.set_valign(Gtk.Align.CENTER)
            btn.set_sensitive(ol["reachable"] and not r["installed"] and r["fit"]["level"] != "too_big" and not self._busy)
            btn.connect("clicked", lambda _b, rr=r: self._on_download(rr))
            row.append(btn)

        # 3. Your models
        c = self._section(3, "Choose the model the investigator uses", "done" if s.get("chosen") else ("todo" if ol["models"] else "wait"))
        if not ol["models"]:
            c.append(_label("Nothing downloaded yet.", "omega-dim"))
        for m in s["installed_models"]:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            c.append(row)
            info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1, hexpand=True)
            row.append(info)
            info.append(_label(m["tag"] + ("   ·   in use" if m["chosen"] else ""), "update-name"))
            g = m["grade"]
            css = GRADE_CSS.get(g.get("grade"), ("", "omega-dim"))[1] if g["state"] != "ungraded" else "omega-dim"
            info.append(_label("Quality check: " + grade_summary(g), css))
            use = Gtk.Button(label="In use" if m["chosen"] else "Use this one")
            use.set_valign(Gtk.Align.CENTER)
            use.set_sensitive(not m["chosen"] and not self._busy)
            use.connect("clicked", lambda _b, t=m["tag"]: self._on_use(t))
            row.append(use)
            chk = Gtk.Button(label="Run quality check")
            chk.set_valign(Gtk.Align.CENTER)
            chk.set_sensitive(not self._busy)
            chk.connect("clicked", lambda _b, t=m["tag"]: self._on_grade(t))
            row.append(chk)
        if step == "grade":
            c.append(_label("Next: run the quality check on the model you chose before relying on it.", "omega-warning"))
        if step == "done":
            c.append(_label("All set. The investigator uses this model, and it has been graded.", "omega-heading"))

    # ---- actions ----------------------------------------------------------------
    def _progress(self, text: str) -> tuple[Gtk.ProgressBar, Gtk.Label, Gtk.Button]:
        _clear(self.progress_box)
        _clear(self.result_box)
        label = _label(text, "omega-dim")
        bar = Gtk.ProgressBar()
        stop = Gtk.Button(label="Cancel", halign=Gtk.Align.START)
        self.progress_box.append(label)
        self.progress_box.append(bar)
        self.progress_box.append(stop)
        return bar, label, stop

    def _finish(self) -> None:
        self._busy = False
        self._cancel = None
        _clear(self.progress_box)

    def _on_download(self, r: dict) -> None:
        free = (self._status.get("hardware") or {}).get("disk_free_gb")
        confirm(self, f"Download {r['title']}?",
                f"This downloads about {r['gb']} GB from Ollama's model library to this laptop" + (f" ({free} GB free)." if free else ".") +
                " It can take a while on a slow connection and you can cancel any time; Ollama resumes where it stopped.\n\nOnly the model file comes down: "
                "nothing about your laptop is sent.", "Download", lambda: self._download(r), destructive=False)

    def _download(self, r: dict) -> None:
        self._busy = True
        bar, label, stop = self._progress(f"Downloading {r['tag']}…")
        errors: list[str] = []

        def on_line(line: str) -> None:
            if line.startswith("PROGRESS "):
                parts = line.split(" ", 2)
                if parts[1].isdigit():
                    bar.set_fraction(int(parts[1]) / 100)
                    label.set_label(f"Downloading {r['tag']}… {parts[1]}%")
            elif line.startswith("[error]"):
                errors.append(line.removeprefix("[error]").strip())

        def on_done(code: int) -> None:
            self._finish()
            if code == 0:
                self._toast(f"{r['tag']} downloaded")
            else:
                self.result_box.append(_label("The download didn't finish: " + (errors[-1] if errors else "cancelled") + ". You can start it again; it resumes.", "omega-critical"))
            self.refresh()

        self._cancel = run_streaming_async("local_ai.py", ["--pull", r["tag"]], on_line, on_done)
        stop.connect("clicked", lambda _b: self._cancel and self._cancel())

    def _on_use(self, tag: str) -> None:
        def done(code: int, lines: list[str]) -> None:
            self._toast(lines[-1] if lines else "Done")
            self.refresh()

        run_sync_async("local_ai.py", ["--use", tag], done, timeout=30.0)

    def _on_grade(self, tag: str) -> None:
        self._busy = True
        self._render()
        bar, label, stop = self._progress(f"Quality-checking {tag}… this runs about 17 made-up incidents through the model and can take several minutes.")
        errors: list[str] = []
        final: list[str] = []

        def on_line(line: str) -> None:
            if line.startswith("PROGRESS "):
                try:
                    frac, _, name = line[9:].partition(" ")
                    i, n = frac.split("/")
                    bar.set_fraction((int(i) - 1) / int(n))
                    label.set_label(f"Quality-checking {tag}: {i} of {n}. {name}")
                except ValueError:
                    pass
            elif line.startswith("{"):
                final.append(line)
            elif line.startswith("[error]"):
                errors.append(line.removeprefix("[error]").strip())

        def on_done(code: int) -> None:
            self._finish()
            if code == 0 and final:
                self._show_report(json.loads(final[-1]))
            else:
                self.result_box.append(_label("The check couldn't finish: " + (errors[-1] if errors else "cancelled"), "omega-critical"))
            self.refresh()

        self._cancel = run_streaming_async("ai_eval.py", ["--run", "--model", tag, "--json"], on_line, on_done)
        stop.connect("clicked", lambda _b: self._cancel and self._cancel())

    def _show_report(self, rep: dict) -> None:
        card_css, _lbl = GRADE_CSS.get(rep["grade"], ("activity-warn", ""))
        banner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        banner.add_css_class("activity-banner")
        banner.add_css_class(card_css)
        banner.append(_label(f"{rep['model']}: {rep['grade']}", "activity-headline"))
        banner.append(_label(f"Passed {round(rep['score'] * 100)}% of the test incidents overall, and {round(rep['critical'] * 100)}% of the attack and trick ones."))
        for r in rep["reasons"]:
            banner.append(_label("•  " + r))
        if rep["grade"] == "Good":
            banner.append(_label("Good here means it did well on these made-up cases. It is not a guarantee: keep verifying before you act.", "omega-dim"))
        self.result_box.append(banner)
        failed = [r for r in rep["results"] if not r["passed"]]
        if failed:
            ex = Gtk.Expander(label=f"{len(failed)} test(s) it got wrong")
            inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            for r in failed:
                inner.append(_label(f"{r['label']}: " + "; ".join(r["problems"]), "omega-dim"))
            ex.set_child(inner)
            self.result_box.append(ex)

"""Windows for the AI investigator: settings, and an investigation you can read, question and verify.

Principles shown in the UI itself: you see exactly what would be sent (redacted) before anything leaves; cloud use needs
your click every time; the AI only suggests, nothing it says runs on its own; and it never overrules the sensors.
"""
from __future__ import annotations

import json

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk, Pango  # noqa: E402

from linuxguardian_ui import scan_history  # noqa: E402,F401  (puts the suite dir on sys.path)
from linuxguardian_ui.clipboard import copy_text  # noqa: E402
from linuxguardian_ui.scripts import run_sync_async  # noqa: E402

VERDICT = {
    "likely_benign": ("Looks harmless", "activity-ok", "omega-heading"),
    "unclear": ("Can't tell", "activity-info", "omega-dim"),
    "suspicious": ("Looks suspicious", "activity-warn", "omega-warning"),
    "likely_malicious": ("Looks malicious", "activity-fail", "omega-critical"),
}
RISK_CSS = {"low": "omega-heading", "medium": "omega-warning", "high": "omega-critical"}
CLAUDE_MODELS = ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"]
BACKENDS = [("off", "Off"), ("ollama", "Local model (Ollama): everything stays on this laptop"),
            ("anthropic", "Claude (Anthropic API): sends the redacted evidence to Anthropic")]


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
    except json.JSONDecodeError:
        return {"error": " ".join(lines)[:300] or "No answer."}


# ====================================================================== settings
class AiSettingsWindow(Gtk.Window):
    def __init__(self, parent: Gtk.Window, toast_overlay: Adw.ToastOverlay | None, on_saved=None) -> None:
        super().__init__(transient_for=parent, modal=True, title="AI investigator settings")
        self.set_default_size(640, 620)
        self._toast_overlay, self._on_saved, self._status = toast_overlay, on_saved, {}
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.set_child(scroller)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=18, margin_bottom=18, margin_start=18, margin_end=18)
        scroller.set_child(box)
        head = _label("AI investigator", "omega-heading")
        head.add_css_class("title-3")
        box.append(head)
        box.append(_label("An optional assistant that reads an incident's evidence, weighs it, and explains what it thinks and what to check. "
                          "It is off until you turn it on, and it can only suggest: it can't run anything, silence an alert, or change a file.", "omega-dim"))

        box.append(_label("Where should the thinking happen?", "update-name"))
        self.backend = Gtk.DropDown.new_from_strings([label for _k, label in BACKENDS])
        self.backend.connect("notify::selected", lambda *_: self._sync())
        box.append(self.backend)

        self.local_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.append(self.local_box)
        self.local_box.append(_label("Local model", "update-name"))
        self.local_models = Gtk.DropDown.new_from_strings(["(none found)"])
        self.local_box.append(self.local_models)
        self.local_hint = _label("", "omega-dim")
        self.local_box.append(self.local_hint)

        self.cloud_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.append(self.cloud_box)
        self.cloud_box.append(_label("Claude model", "update-name"))
        self.claude_model = Gtk.DropDown.new_from_strings(CLAUDE_MODELS)
        self.cloud_box.append(self.claude_model)
        self.cloud_box.append(_label("API key", "update-name"))
        key_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.cloud_box.append(key_row)
        self.key_entry = Gtk.PasswordEntry(hexpand=True, show_peek_icon=True)
        key_row.append(self.key_entry)
        save_key = Gtk.Button(label="Save key")
        save_key.connect("clicked", self._on_save_key)
        key_row.append(save_key)
        remove_key = Gtk.Button(label="Remove")
        remove_key.connect("clicked", self._on_remove_key)
        key_row.append(remove_key)
        self.cloud_hint = _label("", "omega-dim")
        self.cloud_box.append(self.cloud_hint)

        box.append(_label("What is removed before anything is shown or sent", "update-name"))
        self.redaction = Gtk.DropDown.new_from_strings(["Standard: secrets, keys, your username, hostname and home path, emails, MAC addresses",
                                                        "Strict: also generalises public IP addresses and flattens file paths"])
        box.append(self.redaction)

        safeguards = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        safeguards.add_css_class("guardian-banner")
        box.append(safeguards)
        safeguards.append(_label("How it keeps you safe", "omega-heading"))
        for line in ("You see exactly what would be sent (already redacted) before anything leaves, and cloud use needs your click every time.",
                     "The evidence reaches the AI as data, and the AI's reply is checked: unknown fields dropped, every suggested command tested.",
                     "Only a short list of read-only checks can get a Run button, and nothing runs until you press it. No shell, no sudo.",
                     "If the AI says something is harmless while the sensors say otherwise, you're told they disagree. The sensors win.",
                     "Everything sent and received is saved in ~/.linuxguardian/ai_log so you can audit it."):
            safeguards.append(_label("•  " + line, "omega-dim"))

        self.result = _label("", None)
        box.append(self.result)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, halign=Gtk.Align.END)
        box.append(row)
        self.test_btn = Gtk.Button(label="Test connection")
        self.test_btn.set_tooltip_text("Sends a tiny message with NO evidence in it, only to check that the backend answers.")
        self.test_btn.connect("clicked", self._on_test)
        row.append(self.test_btn)
        close = Gtk.Button(label="Close")
        close.connect("clicked", lambda _b: self.close())
        row.append(close)
        save = Gtk.Button(label="Save")
        save.add_css_class("suggested-action")
        save.connect("clicked", self._on_save)
        row.append(save)
        self._load()

    def _toast(self, text: str) -> None:
        if self._toast_overlay is not None:
            self._toast_overlay.add_toast(Adw.Toast.new(text))

    def _load(self) -> None:
        def done(code: int, lines: list[str]) -> None:
            self._status = _parse(lines)
            cfg = self._status.get("config", {})
            keys = [k for k, _l in BACKENDS]
            self.backend.set_selected(keys.index(cfg.get("backend", "off")) if cfg.get("backend") in keys else 0)
            models = self._status.get("ollama_models") or []
            self.local_models.set_model(Gtk.StringList.new(models or ["(none found)"]))
            if cfg.get("ollama_model") in models:
                self.local_models.set_selected(models.index(cfg["ollama_model"]))
            if cfg.get("model") in CLAUDE_MODELS:
                self.claude_model.set_selected(CLAUDE_MODELS.index(cfg["model"]))
            self.redaction.set_selected(1 if cfg.get("redaction") == "strict" else 0)
            self.local_hint.set_label("Ollama is running." if self._status.get("ollama_reachable") else
                                      "Ollama isn't running. Install it from ollama.com, run `ollama serve`, then `ollama pull <a model>` (8 GB of GPU memory handles 7-8B models well).")
            sdk = self._status.get("sdk_installed")
            self.cloud_hint.set_label(("Anthropic's SDK is installed. " if sdk else "Install Anthropic's official SDK first:  pip install anthropic.  ")
                                      + ("An API key is saved." if self._status.get("key_present") else "No API key yet (or set ANTHROPIC_API_KEY)."))
            self._sync()

        run_sync_async("ai_investigator.py", ["--status"], done, timeout=30.0)

    def _sync(self) -> None:
        sel = BACKENDS[self.backend.get_selected()][0]
        self.local_box.set_visible(sel == "ollama")
        self.cloud_box.set_visible(sel == "anthropic")
        self.test_btn.set_sensitive(sel != "off")

    def _args(self) -> list[str]:
        sel = BACKENDS[self.backend.get_selected()][0]
        args = ["--configure", "--backend", sel, "--redaction", "strict" if self.redaction.get_selected() == 1 else "standard"]
        if sel == "ollama":
            models = self._status.get("ollama_models") or []
            if models:
                args += ["--ollama-model", models[self.local_models.get_selected()]]
        if sel == "anthropic":
            args += ["--model", CLAUDE_MODELS[self.claude_model.get_selected()]]
        return args

    def _on_save(self, _btn: Gtk.Button) -> None:
        def done(code: int, lines: list[str]) -> None:
            s = _parse(lines)
            problems = s.get("problems") or []
            self.result.set_label("Saved." + ("  Still needed: " + " ".join(problems) if problems else ""))
            self._toast("AI settings saved")
            if self._on_saved:
                self._on_saved()

        run_sync_async("ai_investigator.py", self._args(), done, timeout=30.0)

    def _on_save_key(self, _btn: Gtk.Button) -> None:
        import ai_investigator as backend

        try:
            backend.save_key(self.key_entry.get_text())
        except backend.AiError as exc:
            self.result.set_label(str(exc))
            return
        self.key_entry.set_text("")
        self.result.set_label("API key saved privately (mode 600).")
        self._load()

    def _on_remove_key(self, _btn: Gtk.Button) -> None:
        import ai_investigator as backend

        backend.clear_key()
        self.result.set_label("API key removed.")
        self._load()

    def _on_test(self, _btn: Gtk.Button) -> None:
        self.result.set_label("Testing…")

        def after_save(code: int, lines: list[str]) -> None:
            def done(code2: int, lines2: list[str]) -> None:
                r = _parse(lines2)
                self.result.set_label(f"Works: {r['backend']} / {r['model']} answered." if r.get("ok") else "Didn't work: " + r.get("error", "no answer"))

            run_sync_async("ai_investigator.py", ["--test"], done, timeout=180.0)

        run_sync_async("ai_investigator.py", self._args(), after_save, timeout=30.0)


# ================================================================== investigation
class InvestigationWindow(Gtk.Window):
    def __init__(self, parent: Gtk.Window, incident: dict, toast_overlay: Adw.ToastOverlay | None) -> None:
        super().__init__(transient_for=parent, modal=False, title="Investigate with AI")
        self.set_default_size(760, 760)
        self._incident, self._toast_overlay, self._run_id, self._parent = incident, toast_overlay, "", parent
        self._cloud = False
        self._destination = ""
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.set_child(scroller)
        self.body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=18, margin_bottom=18, margin_start=18, margin_end=18)
        scroller.set_child(self.body)
        head = _label(incident["title"], "omega-heading")
        head.add_css_class("title-3")
        self.body.append(head)
        self.stage = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.body.append(self.stage)
        self.results = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.body.append(self.results)
        self.stage.append(_label("Preparing the evidence…", "omega-dim"))
        run_sync_async("ai_investigator.py", ["--status"], self._on_status, timeout=30.0)

    def _toast(self, text: str) -> None:
        if self._toast_overlay is not None:
            self._toast_overlay.add_toast(Adw.Toast.new(text))

    # ---- stage 1: preview
    def _on_status(self, code: int, lines: list[str]) -> None:
        st = _parse(lines)
        _clear(self.stage)
        if not st.get("configured"):
            self.stage.append(_label("The AI investigator isn't set up yet." + (" " + " ".join(st.get("problems", [])) if st.get("problems") else ""), "omega-warning"))
            btn = Gtk.Button(label="Open AI settings", halign=Gtk.Align.START)
            btn.add_css_class("suggested-action")
            btn.connect("clicked", lambda _b: AiSettingsWindow(self, self._toast_overlay, on_saved=lambda: run_sync_async("ai_investigator.py", ["--status"], self._on_status, timeout=30.0)).present())
            self.stage.append(btn)
            return
        self._cloud = st["config"]["backend"] == "anthropic"
        run_sync_async("ai_investigator.py", ["--prepare", self._incident["id"]], self._on_prepared, timeout=90.0)

    def _on_prepared(self, code: int, lines: list[str]) -> None:
        p = _parse(lines)
        _clear(self.stage)
        if p.get("error"):
            self.stage.append(_label(p["error"], "omega-critical"))
            return
        self._destination = p["destination"]
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        card.add_css_class("omega-card")
        self.stage.append(card)
        card.append(_label("What will be sent", "update-name"))
        card.append(_label(f"To: {self._destination}", "omega-warning" if self._cloud else "omega-heading"))
        card.append(_label(f"{p['redaction']}  About {p['est_tokens']:,} tokens ({p['chars']:,} characters).", "omega-dim"))
        ex = Gtk.Expander(label="Show exactly what would be sent (already redacted)")
        sc = Gtk.ScrolledWindow(min_content_height=220, max_content_height=320)
        sc.set_child(_label(json.dumps(p["dossier"], indent=1, ensure_ascii=False), selectable=True, mono=True))
        ex.set_child(sc)
        card.append(ex)
        self.question = Gtk.Entry(placeholder_text="Optional: ask something specific (e.g. “could this be my ROS build?”)")
        self.stage.append(self.question)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.stage.append(row)
        label = f"Send to {self._destination.split(' ')[0]} and investigate" if self._cloud else "Investigate (stays on this laptop)"
        go = Gtk.Button(label=label)
        go.add_css_class("suggested-action")
        go.connect("clicked", self._on_go)
        row.append(go)
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda _b: self.close())
        row.append(cancel)
        if self._cloud:
            self.stage.append(_label("Nothing has been sent yet. Cloud use needs this click every time.", "omega-dim"))

    # ---- stage 2: run
    def _on_go(self, btn: Gtk.Button) -> None:
        question = self.question.get_text().strip()
        _clear(self.stage)
        spin_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        spinner = Gtk.Spinner()
        spinner.start()
        spin_row.append(spinner)
        spin_row.append(_label("Investigating… this can take a minute.", "omega-dim"))
        self.stage.append(spin_row)
        args = ["--investigate", self._incident["id"]] + (["--question", question] if question else []) + (["--confirm-cloud"] if self._cloud else [])
        run_sync_async("ai_investigator.py", args, self._on_result, timeout=900.0)

    def _on_result(self, code: int, lines: list[str]) -> None:
        r = _parse(lines)
        _clear(self.stage)
        if r.get("error"):
            self.stage.append(_label(r["error"], "omega-critical"))
            return
        self._run_id = r["id"]
        self.stage.append(_label(f"Done. Saved to ~/.linuxguardian/ai_log/{r['id']}.json (exactly what was sent and received).", "omega-dim"))
        self._show(r["result"], self.results)
        self._add_follow_up()

    def _show(self, res: dict, into: Gtk.Box) -> None:
        text, card_css, label_css = VERDICT[res["verdict"]]
        banner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        banner.add_css_class("activity-banner")
        banner.add_css_class(card_css)
        into.append(banner)
        conf = "very confident" if res["confidence"] >= 0.85 else "fairly confident" if res["confidence"] >= 0.6 else "not very confident" if res["confidence"] >= 0.3 else "guessing"
        top = _label(f"{text}  ·  {conf}", "activity-headline")
        banner.append(top)
        banner.append(_label(res["summary"]))
        if res["sensors_disagree"]:
            warn = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            warn.add_css_class("activity-banner")
            warn.add_css_class("activity-warn")
            warn.append(_label(f"The AI and the sensors disagree. The sensors rate this {self._incident['severity']}. That rating stands: use the checks below to "
                               "confirm before you dismiss it. The AI never marks an incident reviewed.", "activity-headline"))
            into.append(warn)
        if res["injection_suspected"]:
            warn = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            warn.add_css_class("activity-banner")
            warn.add_css_class("activity-fail")
            warn.append(_label("The evidence contains text that tries to give instructions to an AI. That is itself a strong sign of an attack.", "activity-headline"))
            if res["injection_quote"]:
                warn.append(_label(res["injection_quote"], selectable=True, mono=True))
            into.append(warn)

        def section(title: str, items: list[str], css: str | None = None) -> None:
            if not items:
                return
            col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
            col.append(_label(title, "update-name"))
            for i in items:
                col.append(_label("•  " + i, css))
            into.append(col)

        section("How it reasoned", res["reasoning"])
        section("Signs of an attack", res["evidence_for_attack"], "omega-warning")
        section("Signs it's harmless", res["evidence_for_benign"], "omega-heading")
        section("What it's unsure about", res["uncertainties"], "omega-dim")

        if res["next_checks"]:
            into.append(_label("Checks you can run", "update-name"))
            for c in res["next_checks"]:
                card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
                card.add_css_class("omega-card")
                into.append(card)
                if c["why"]:
                    card.append(_label(c["why"], "omega-dim"))
                card.append(_label(c["command"], selectable=True, mono=True))
                out = Gtk.Label(label="", xalign=0, wrap=True, selectable=True)
                out.add_css_class("update-raw")
                out.set_visible(False)
                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                card.append(row)
                cp = Gtk.Button(label="Copy")
                cp.connect("clicked", lambda _b, cmd=c["command"]: (copy_text(cmd), self._toast("Command copied")))
                row.append(cp)
                if c["runnable"]:
                    run = Gtk.Button(label="Run (read-only)")
                    run.connect("clicked", lambda _b, cmd=c["command"], o=out: self._run_check(cmd, o))
                    row.append(run)
                else:
                    row.append(_label(c["note"], "omega-warning" if c["risky"] else "omega-dim"))
                card.append(out)

        if res["recommended_actions"]:
            into.append(_label("Suggested actions (LinuxGuardian will not do these for you)", "update-name"))
            for a in res["recommended_actions"]:
                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
                chip = Gtk.Label(label=a["risk"].title() + " risk", valign=Gtk.Align.START)
                chip.add_css_class("impact-badge")
                chip.add_css_class(RISK_CSS[a["risk"]])
                row.append(chip)
                col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1, hexpand=True)
                col.append(_label(a["action"]))
                if a["why"]:
                    col.append(_label(a["why"], "omega-dim"))
                row.append(col)
                into.append(row)
        into.append(_label("The AI can be wrong. It only saw the redacted evidence shown above, and it is advice, not a verdict.", "omega-dim"))

    def _run_check(self, cmd: str, out: Gtk.Label) -> None:
        out.set_visible(True)
        out.set_label("Running…")

        def done(code: int, lines: list[str]) -> None:
            r = _parse(lines)
            out.set_label(r.get("output") or ("Not run: " + r.get("reason", r.get("error", "no output"))) or "(no output)")

        run_sync_async("ai_investigator.py", ["--run-check", cmd], done, timeout=40.0)

    # ---- follow-up
    def _add_follow_up(self) -> None:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.add_css_class("omega-card")
        self.body.append(box)
        box.append(_label("Ask a follow-up", "update-name"))
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        box.append(row)
        self.followup = Gtk.Entry(hexpand=True, placeholder_text="For example: “what does that port belong to?”")
        row.append(self.followup)
        ask = Gtk.Button(label="Ask")
        ask.connect("clicked", self._on_ask)
        row.append(ask)
        self.turns = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.append(self.turns)

    def _on_ask(self, _btn: Gtk.Button) -> None:
        q = self.followup.get_text().strip()
        if not q:
            return

        def go() -> None:
            self.turns.append(_label("Thinking…", "omega-dim"))
            args = ["--follow-up", self._run_id, "--question", q] + (["--confirm-cloud"] if self._cloud else [])

            def done(code: int, lines: list[str]) -> None:
                r = _parse(lines)
                _clear(self.turns)
                if r.get("error"):
                    self.turns.append(_label(r["error"], "omega-critical"))
                    return
                self.turns.append(_label("You asked: " + q, "update-name"))
                self._show(r["turn"]["result"], self.turns)
                self.followup.set_text("")

            run_sync_async("ai_investigator.py", args, done, timeout=900.0)

        if self._cloud:
            from linuxguardian_ui.dialogs import confirm

            confirm(self, "Send your question?", f"This sends the same redacted evidence plus your question to {self._destination}.", "Send", go, destructive=False)
        else:
            go()

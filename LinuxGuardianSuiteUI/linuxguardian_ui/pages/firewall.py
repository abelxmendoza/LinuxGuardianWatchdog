"""Firewall tab: the ufw firewall at a glance, and every control for it in one place.

Reading the state needs no password (ufw's settings files, the service, the block log). Reading the rules and every
change go through linux_firewall.sh: one fixed root script, one password prompt, a confirmation first, and the rules
read back afterwards so the list always shows what root actually did. Nothing changes on its own.
"""
from __future__ import annotations

import json
from collections.abc import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

from linuxguardian_ui import scan_history  # noqa: E402,F401  (puts the suite dir on sys.path)
from linuxguardian_ui.clipboard import copy_text  # noqa: E402
from linuxguardian_ui.components import section_header  # noqa: E402
from linuxguardian_ui.dialogs import confirm  # noqa: E402
from linuxguardian_ui.scripts import run_streaming_async, run_sync_async  # noqa: E402

import firewall_control as fc  # noqa: E402

SCRIPT = "linux_firewall.sh"
LEVEL_CSS = {"ok": "omega-heading", "info": "omega-heading", "warning": "omega-warning", "critical": "omega-critical"}
ACTION_LABELS = [("allow", "Allow"), ("limit", "Limit (allow, slow down guessing)"), ("deny", "Deny (drop silently)"), ("reject", "Reject (refuse)")]
PROTO_LABELS = [("tcp", "TCP"), ("udp", "UDP"), ("any", "TCP + UDP")]
RESULT_TOASTS = {0: "Firewall updated", 2: "Cancelled: nothing was changed", 3: "Refused: nothing was changed",
                 4: "The rule list changed first: nothing was deleted"}


def _label(text: str, css: str | None = None, *, selectable: bool = False) -> Gtk.Label:
    label = Gtk.Label(label=text, xalign=0, wrap=True, selectable=selectable)
    if css:
        label.add_css_class(css)
    return label


def _chip(text: str, css: str) -> Gtk.Label:
    chip = Gtk.Label(label=text)
    chip.add_css_class("omega-metric")
    chip.add_css_class(css)
    return chip


def _card() -> Gtk.Box:
    card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    card.add_css_class("omega-card")
    return card


def _clear(box: Gtk.Box) -> None:
    while (child := box.get_first_child()) is not None:
        box.remove(child)


def rules_from_output(lines: list[str]) -> dict | None:
    """The `ufw status numbered` block the root script prints between markers, parsed; None if it printed none."""
    try:
        start = lines.index("LG_RULES_BEGIN")
        end = lines.index("LG_RULES_END", start)
    except ValueError:
        return None
    return fc.parse_numbered("\n".join(lines[start + 1:end]))


class FirewallPage(Gtk.Box):
    def __init__(self, toast_overlay: Adw.ToastOverlay, open_exposure: Callable[[], None] | None = None) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self._toast_overlay = toast_overlay
        self.set_margin_top(16)
        self.set_margin_bottom(16)
        self.set_margin_start(16)
        self.set_margin_end(16)

        self._status: dict = {}
        self._rules: dict | None = None            # None until root has shown them
        self._blocks: dict = {}
        self._busy = False
        self._planned = False                      # True once the CURRENT add-rule inputs have been previewed
        self._status_buttons: list[Gtk.Widget] = []
        self._rule_buttons: list[Gtk.Widget] = []

        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.append(toolbar)
        self.refresh_btn = Gtk.Button(label="Refresh")
        self.refresh_btn.add_css_class("suggested-action")
        self.refresh_btn.connect("clicked", lambda _b: self.refresh())
        toolbar.append(self.refresh_btn)
        self.rules_btn = Gtk.Button(label="Show rules…")
        self.rules_btn.set_tooltip_text("ufw only shows its rules to an administrator: one password prompt, read-only")
        self.rules_btn.connect("clicked", lambda _b: self.load_rules())
        toolbar.append(self.rules_btn)
        copy_btn = Gtk.Button(label="Copy All")
        copy_btn.connect("clicked", self._on_copy_all)
        toolbar.append(copy_btn)
        if open_exposure is not None:
            exposure_btn = Gtk.Button(label="What is listening?")
            exposure_btn.set_tooltip_text("Open the Exposure tab: the ports this laptop has open, and who can reach them")
            exposure_btn.connect("clicked", lambda _b: open_exposure())
            toolbar.append(exposure_btn)
        self.spinner = Gtk.Spinner()
        toolbar.append(self.spinner)

        self.append(_label(
            "The firewall decides who may connect to this laptop. Looking is free; every change shows you exactly what "
            "it does, asks first, and needs your password once. Nothing here changes on its own.", "omega-dim"))

        scroller = Gtk.ScrolledWindow(vexpand=True)
        self.append(scroller)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        scroller.set_child(content)

        self.status_card = _card()
        content.append(self.status_card)

        content.append(section_header("Defaults"))
        content.append(self._build_defaults())

        content.append(section_header("Rules"))
        self.rules_box = _card()
        content.append(self.rules_box)

        content.append(section_header("Add a rule"))
        content.append(self._build_add_rule())

        content.append(section_header("What the firewall blocked recently"))
        self.blocks_box = _card()
        content.append(self.blocks_box)

        content.append(section_header("Last action"))
        self.output = Gtk.Label(label="Nothing run yet.", xalign=0, wrap=True, selectable=True)
        self.output.add_css_class("monospace")
        self.output.add_css_class("omega-dim")
        content.append(self.output)

        self._render_rules()
        self.refresh()

    # ------------------------------------------------------------------ reading (no password)
    def refresh(self) -> None:
        self.spinner.start()
        self.refresh_btn.set_sensitive(False)
        pending = {"n": 2}

        def finished() -> None:
            pending["n"] -= 1
            if pending["n"] == 0:
                self.spinner.stop()
                self.refresh_btn.set_sensitive(True)

        def on_status(code: int, lines: list[str]) -> None:
            self._status = self._json(lines)
            self._render_status()
            finished()

        def on_blocks(code: int, lines: list[str]) -> None:
            self._blocks = self._json(lines)
            self._render_blocks()
            finished()

        run_sync_async(SCRIPT, ["--status", "--json"], on_status, timeout=20.0)
        run_sync_async(SCRIPT, ["--blocks", "--json"], on_blocks, timeout=20.0)

    @staticmethod
    def _json(lines: list[str]) -> dict:
        for line in lines:
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except ValueError:
                    pass
        return {}

    # ------------------------------------------------------------------ status card
    def _render_status(self) -> None:
        _clear(self.status_card)
        st = self._status
        if not st:
            self.status_card.append(_label("Couldn't read the firewall's state. Try Refresh.", "omega-warning"))
            return
        head = Gtk.Label(label=st["headline"], xalign=0, wrap=True)
        head.add_css_class("title-2")
        head.add_css_class(LEVEL_CSS.get(st["level"], "omega-heading"))
        self.status_card.append(head)
        self.status_card.append(_label(st["advice"], "omega-dim", selectable=True))

        chips = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, max_children_per_line=8, column_spacing=6, row_spacing=6)
        pol = st.get("policies") or {}
        service = st.get("service", "unknown")
        for text, css in (
            (f"Service: {service}", "omega-metric-normal" if service == "active" else "omega-metric-warning"),
            (f"Incoming: {pol.get('incoming') or '?'}", "omega-metric-normal" if pol.get("incoming") in fc.INCOMING_POLICIES else "omega-metric-critical"),
            (f"Outgoing: {pol.get('outgoing') or '?'}", "omega-metric-dim"),
            (f"Routed: {pol.get('routed') or '?'}", "omega-metric-dim"),
            (f"Logging: {st.get('logging', '?')}", "omega-metric-warning" if st.get("logging") == "off" else "omega-metric-dim"),
            (f"IPv6: {'on' if st.get('ipv6') else 'off'}", "omega-metric-dim"),
        ):
            chips.append(_chip(text, css))
        self.status_card.append(chips)

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.status_card.append(buttons)
        self._status_buttons = []
        controllable = st.get("installed") and st.get("kind") not in ("firewalld", "nftables")
        if controllable:
            if st.get("enabled"):
                off = Gtk.Button(label="Turn firewall off…")
                off.add_css_class("destructive-action")
                off.connect("clicked", lambda _b: self._confirm_simple(
                    "Turn the firewall off?",
                    "Every program listening on this laptop becomes reachable from every network you are on, until you "
                    "turn it back on. Your rules are kept and come back when you do.\n\nThis is recorded as a warning, so the "
                    "Defenses monitor will also report it.", "Turn off", ["--disable"], destructive=True))
                buttons.append(off)
                self._status_buttons.append(off)
            else:
                on = Gtk.Button(label="Turn firewall on…")
                on.add_css_class("suggested-action")
                on.connect("clicked", lambda _b: self._confirm_simple(
                    "Turn the firewall on?",
                    "Connections coming in are blocked unless a rule allows them; connections going out keep working. If you "
                    "reach this laptop over SSH from another machine, add an SSH rule first.", "Turn on", ["--enable"]))
                buttons.append(on)
                self._status_buttons.append(on)
            if st.get("enabled") and service != "active":
                restart = Gtk.Button(label="Restart firewall…")
                restart.connect("clicked", lambda _b: self._confirm_simple(
                    "Restart the firewall service?",
                    "ufw reloads every rule from its files. If a rule file is broken it fails again, and the reason is shown "
                    "under Last action.", "Restart", ["--restart"]))
                buttons.append(restart)
                self._status_buttons.append(restart)
        self._sync_defaults()
        self._set_busy(self._busy)

    # ------------------------------------------------------------------ defaults
    def _build_defaults(self) -> Gtk.Widget:
        card = _card()
        card.append(_label(
            "What happens to a connection no rule mentions. Deny is the safe default for incoming: rules then open only "
            "what you need. 'Allow everything in' isn't offered; if you need that, turning the firewall off says so honestly.",
            "omega-dim"))
        grid = Gtk.Grid(column_spacing=12, row_spacing=8)
        card.append(grid)
        self._defaults: dict[str, tuple[Gtk.DropDown, tuple[str, ...], Gtk.Button]] = {}
        rows = (
            ("incoming", "Incoming connections", fc.INCOMING_POLICIES, "--default-incoming"),
            ("outgoing", "Outgoing connections", fc.OUTGOING_POLICIES, "--default-outgoing"),
            ("logging", "Logging", fc.LOG_LEVELS, "--logging"),
        )
        for row, (key, title, choices, flag) in enumerate(rows):
            grid.attach(Gtk.Label(label=title, xalign=0, hexpand=True), 0, row, 1, 1)
            drop = Gtk.DropDown.new_from_strings(list(choices))
            grid.attach(drop, 1, row, 1, 1)
            button = Gtk.Button(label="Change…")
            button.set_sensitive(False)
            button.connect("clicked", lambda _b, k=key, f=flag: self._confirm_default(k, f))
            grid.attach(button, 2, row, 1, 1)
            drop.connect("notify::selected", lambda *_a: self._sync_default_buttons())
            self._defaults[key] = (drop, choices, button)
        return card

    def _current_default(self, key: str) -> str | None:
        if key == "logging":
            return self._status.get("logging")
        return (self._status.get("policies") or {}).get(key)

    def _chosen_default(self, key: str) -> str:
        drop, choices, _button = self._defaults[key]
        return choices[drop.get_selected()]

    def _sync_defaults(self) -> None:
        for key, (drop, choices, _button) in self._defaults.items():
            current = self._current_default(key)
            if current in choices:
                drop.set_selected(choices.index(current))
        self._sync_default_buttons()

    def _sync_default_buttons(self) -> None:
        ok = bool(self._status.get("installed")) and self._status.get("kind") not in ("firewalld", "nftables")
        for key, (_drop, _choices, button) in self._defaults.items():
            button.set_sensitive(ok and not self._busy and self._chosen_default(key) != self._current_default(key))

    def _confirm_default(self, key: str, flag: str) -> None:
        value = self._chosen_default(key)
        body = {
            ("incoming", "deny"): "Connections that no rule allows are dropped without an answer.",
            ("incoming", "reject"): "Connections that no rule allows are refused straight away. Slightly friendlier for your own "
                                    "tools on the network, and tells a scanner the laptop is there.",
            ("outgoing", "allow"): "Programs on this laptop may connect out anywhere unless a rule says otherwise (the usual setting).",
            ("outgoing", "deny"): "Programs on this laptop may NOT connect out unless a rule allows it. Web browsing, updates and "
                                  "DNS stop working until you add 'out' rules with ufw by hand. Only for locked-down machines.",
        }.get((key, value), f"ufw will log {value} detail to /var/log/ufw.log. 'low' records blocked connections, which the "
                            "'blocked recently' section below reads; 'off' leaves it empty.")
        what = "Logging" if key == "logging" else f"Default for {key} connections"
        self._confirm_simple(f"{what}: {value}?", body + "\n\nYour desktop will ask for your password.", "Change", [flag, value],
                             destructive=(key, value) == ("outgoing", "deny"))

    # ------------------------------------------------------------------ rules
    def load_rules(self) -> None:
        self._run(["--rules"], quiet=True)

    def _render_rules(self) -> None:
        _clear(self.rules_box)
        self._rule_buttons = []
        if self._rules is None:
            self.rules_box.append(_label(
                "ufw only shows its rules to an administrator. 'Show rules…' asks for your password once and only reads.",
                "omega-dim"))
            return
        if self._rules.get("active") is False:
            self.rules_box.append(_label(
                "The firewall is off, so no rules are in force. Saved rules come back when you turn it on.", "omega-warning"))
            return
        rules = self._rules.get("rules") or []
        if not rules:
            self.rules_box.append(_label(
                "No rules: everything coming in follows the default above, and nothing is opened as an exception.", "omega-dim"))
            return
        ours = sum(1 for r in rules if r["ours"])
        self.rules_box.append(_label(
            f"{len(rules)} rule(s), checked top to bottom; the first that matches wins. {ours} added from LinuxGuardian.", "omega-dim"))
        listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.rules_box.append(listbox)
        for rule in rules:
            listbox.append(self._rule_row(rule))

    def _rule_row(self, rule: dict) -> Gtk.Widget:
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12, margin_top=6, margin_bottom=6, margin_start=6, margin_end=6)
        num = Gtk.Label(label=f"{rule['num']}", width_chars=3, xalign=1)
        num.add_css_class("omega-dim")
        row.append(num)
        css = {"allow": "omega-metric-normal", "limit": "omega-metric-warning"}.get(rule["action"], "omega-metric-critical")
        row.append(_chip(rule["action"].upper(), css))
        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
        text.append(Gtk.Label(label=fc.describe_rule(rule), xalign=0, wrap=True))
        detail = f"{rule['to']}  ←  {rule['from']}  ({rule['direction']}{', IPv6' if rule['v6'] else ''})"
        if rule["comment"]:
            detail += f"   # {rule['comment']}"
        text.append(_label(detail, "omega-dim", selectable=True))
        row.append(text)
        if rule["action"] == "allow" and rule["from"].startswith("Anywhere") and rule["direction"] == "in":
            row.append(_chip("open to anyone", "omega-metric-warning"))
        delete = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER)
        delete.add_css_class("flat")
        delete.set_tooltip_text(f"Delete rule {rule['num']}…")
        delete.connect("clicked", lambda _b, r=rule: self._confirm_delete(r))
        row.append(delete)
        self._rule_buttons.append(delete)
        return row

    def _confirm_delete(self, rule: dict) -> None:
        confirm(
            self.get_root(),
            f"Delete rule {rule['num']}?",
            f"{fc.describe_rule(rule)}.\n\n{rule['line']}\n\nOnly this rule is removed, and only if it is still rule "
            f"{rule['num']} when root looks (if the list changed meanwhile, nothing is deleted). Your desktop will ask for your password.",
            "Delete rule",
            lambda: self._run(["--delete", str(rule["num"]), "--fingerprint", rule["fingerprint"]]),
            destructive=True,
        )

    # ------------------------------------------------------------------ add a rule
    def _build_add_rule(self) -> Gtk.Widget:
        card = _card()
        card.append(_label(
            "Open (or close) one port. Narrow is better: put the address of the one machine or network that needs it in "
            "'From'. You see the exact ufw command before anything happens.", "omega-dim"))
        grid = Gtk.Grid(column_spacing=12, row_spacing=8)
        card.append(grid)

        self.preset_drop = Gtk.DropDown.new_from_strings(["Custom", *fc.PRESETS])
        self.preset_drop.connect("notify::selected", lambda *_a: self._apply_preset())
        self.action_drop = Gtk.DropDown.new_from_strings([label for _k, label in ACTION_LABELS])
        self.port_entry = Gtk.Entry(placeholder_text="22, or a range like 6000:6010", hexpand=True)
        self.proto_drop = Gtk.DropDown.new_from_strings([label for _k, label in PROTO_LABELS])
        self.from_entry = Gtk.Entry(placeholder_text="Anyone (leave empty), or 192.168.1.50, or 192.168.1.0/24", hexpand=True)
        self.label_entry = Gtk.Entry(placeholder_text="Optional note, e.g. home NAS", max_length=40, hexpand=True)
        for row, (title, widget) in enumerate((("Common", self.preset_drop), ("Action", self.action_drop), ("Port", self.port_entry),
                                               ("Protocol", self.proto_drop), ("From", self.from_entry), ("Label", self.label_entry))):
            grid.attach(Gtk.Label(label=title, xalign=0), 0, row, 1, 1)
            grid.attach(widget, 1, row, 1, 1)
        for widget in (self.port_entry, self.from_entry, self.label_entry):
            widget.connect("changed", lambda *_a: self._inputs_changed())
        for drop in (self.action_drop, self.proto_drop):
            drop.connect("notify::selected", lambda *_a: self._inputs_changed())

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        card.append(buttons)
        self.preview_btn = Gtk.Button(label="Preview rule")
        self.preview_btn.connect("clicked", lambda _b: self._preview())
        buttons.append(self.preview_btn)
        self.add_btn = Gtk.Button(label="Add rule…")
        self.add_btn.add_css_class("suggested-action")
        self.add_btn.set_sensitive(False)
        self.add_btn.connect("clicked", lambda _b: self._confirm_add())
        buttons.append(self.add_btn)
        self.plan_label = Gtk.Label(label="", xalign=0, wrap=True, selectable=True)
        self.plan_label.add_css_class("monospace")
        card.append(self.plan_label)
        return card

    def _apply_preset(self) -> None:
        index = self.preset_drop.get_selected()
        if index == 0:
            return
        port, proto = fc.PRESETS[list(fc.PRESETS)[index - 1]]
        self.port_entry.set_text(port)
        self.proto_drop.set_selected([k for k, _l in PROTO_LABELS].index(proto))
        if not self.label_entry.get_text():
            self.label_entry.set_text(list(fc.PRESETS)[index - 1].split(" (")[0].replace("/", "-")[:40])

    def _add_args(self) -> list[str]:
        return ["--action", ACTION_LABELS[self.action_drop.get_selected()][0], "--port", self.port_entry.get_text().strip(),
                "--proto", PROTO_LABELS[self.proto_drop.get_selected()][0], "--from", self.from_entry.get_text().strip(),
                "--label", self.label_entry.get_text().strip()]

    def _inputs_changed(self) -> None:
        # Any edit invalidates the preview: you can only add exactly what you were shown.
        self._planned = False
        self.add_btn.set_sensitive(False)

    def _preview(self) -> None:
        def done(code: int, lines: list[str]) -> None:
            self.plan_label.set_label("\n".join(lines))
            self.plan_label.remove_css_class("omega-warning")
            if code != 0:
                self.plan_label.add_css_class("omega-warning")
            self._planned = code == 0
            self.add_btn.set_sensitive(self._planned and not self._busy)

        run_sync_async(SCRIPT, ["--plan-add", *self._add_args()], done, timeout=20.0)

    def _confirm_add(self) -> None:
        if not self._planned or self._busy:
            return
        confirm(
            self.get_root(),
            "Add this firewall rule?",
            self.plan_label.get_label() + "\n\nYour desktop will ask for your password.",
            "Add rule",
            lambda: self._run(["--add", *self._add_args()]),
            destructive=False,
        )

    # ------------------------------------------------------------------ recent blocks
    def _render_blocks(self) -> None:
        _clear(self.blocks_box)
        b = self._blocks
        if not b:
            self.blocks_box.append(_label("Couldn't read the firewall log.", "omega-dim"))
            return
        if not b.get("readable"):
            self.blocks_box.append(_label(b.get("reason", "The firewall log can't be read."), "omega-dim"))
            return
        if not b.get("total"):
            self.blocks_box.append(_label("Nothing blocked in the recent log.", "omega-dim"))
            return
        self.blocks_box.append(Gtk.Label(
            label=f"{b['total']} connections blocked ({b['inbound']} coming in, {b['outbound']} going out), {b['first']} to {b['last']}",
            xalign=0, wrap=True))
        self.blocks_box.append(_label(
            "Most of this is normal background noise: late replies to connections that already ended, devices announcing "
            "themselves on the local network, and scanners on the internet. Worth a look: one internet address showing up "
            "far more than others, or blocks on a port you expected to be open.", "omega-dim"))
        columns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=24, homogeneous=True)
        self.blocks_box.append(columns)
        for title, items in (("From", [(s["addr"], f"{s['count']}  ·  {s['kind']}") for s in b.get("top_sources", [])]),
                             ("To port", [(p["port"], str(p["count"])) for p in b.get("top_ports", [])])):
            col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            heading = Gtk.Label(label=title, xalign=0)
            heading.add_css_class("omega-heading")
            col.append(heading)
            for name, value in items:
                line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                line.append(Gtk.Label(label=name, xalign=0, hexpand=True, selectable=True))
                count = Gtk.Label(label=value, xalign=1)
                count.add_css_class("omega-dim")
                line.append(count)
                col.append(line)
            columns.append(col)

    # ------------------------------------------------------------------ running changes
    def _confirm_simple(self, heading: str, body: str, label: str, args: list[str], destructive: bool = False) -> None:
        if self._busy:
            return
        confirm(self.get_root(), heading, body, label, lambda: self._run(args), destructive=destructive)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        for button in (self.rules_btn, *self._status_buttons, *self._rule_buttons):
            button.set_sensitive(not busy)
        self.add_btn.set_sensitive(self._planned and not busy)
        if busy:
            self.spinner.start()
        else:
            self.spinner.stop()
        self._sync_default_buttons()

    def _run(self, args: list[str], quiet: bool = False) -> None:
        if self._busy:
            return
        self._set_busy(True)
        lines: list[str] = []

        def on_line(line: str) -> bool:
            lines.append(line)
            shown = [entry for entry in lines if not entry.startswith("LG_RULES")]
            self.output.set_label("\n".join(shown[-14:]))
            return False

        def on_done(code: int) -> bool:
            self._set_busy(False)
            parsed = rules_from_output(lines)
            if parsed is not None:
                self._rules = parsed
                self._render_rules()
            if not quiet or code != 0:
                self._toast_overlay.add_toast(Adw.Toast.new(RESULT_TOASTS.get(code, "ufw reported an error (see Last action)")))
            if not quiet:
                self._inputs_changed()
                self.refresh()
            return False

        run_streaming_async(SCRIPT, args, on_line, on_done)

    # ------------------------------------------------------------------ copy
    def _on_copy_all(self, _btn: Gtk.Button) -> None:
        if not self._status:
            self._toast_overlay.add_toast(Adw.Toast(title="Nothing to copy yet", timeout=2))
            return
        try:
            copy_text(self.as_text())
        except Exception as exc:  # noqa: BLE001
            self._toast_overlay.add_toast(Adw.Toast(title=f"Copy failed: {exc}", timeout=3))
            return
        self._toast_overlay.add_toast(Adw.Toast(title="Firewall report copied", timeout=2))

    def as_text(self) -> str:
        st = self._status
        pol = st.get("policies") or {}
        lines = ["LinuxGuardian Watchdog — firewall report", st.get("headline", ""), st.get("advice", ""),
                 f"Service: {st.get('service')}  Logging: {st.get('logging')}  IPv6: {st.get('ipv6')}",
                 f"Defaults: incoming {pol.get('incoming')}, outgoing {pol.get('outgoing')}, routed {pol.get('routed')}", ""]
        if self._rules is None:
            lines.append("Rules: not read (needs administrator).")
        else:
            lines.append("Rules:")
            lines += [f"  [{r['num']}] {r['line'].split(']', 1)[1].strip()}  — {fc.describe_rule(r)}" for r in self._rules.get("rules", [])] or ["  none"]
        b = self._blocks
        if b.get("readable") and b.get("total"):
            lines += ["", f"Blocked recently: {b['total']} ({b['inbound']} in, {b['outbound']} out), {b['first']} to {b['last']}"]
            lines += [f"  from {s['addr']} ({s['kind']}): {s['count']}" for s in b.get("top_sources", [])]
            lines += [f"  to {p['port']}: {p['count']}" for p in b.get("top_ports", [])]
        return "\n".join(lines) + "\n"

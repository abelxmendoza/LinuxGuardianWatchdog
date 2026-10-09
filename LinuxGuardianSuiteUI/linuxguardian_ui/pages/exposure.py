"""Exposure page — what is listening on this laptop and who can reach it.

DETECTION ONLY. Nothing on this page closes a port, stops a service, or
changes the firewall; it reports what the kernel says and what it likely
means. Where a normal user can't see something (the owner of a root-run
service, firewall allow-rules) it says so instead of guessing.
"""
from __future__ import annotations

import json

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

from linuxguardian_ui.clipboard import copy_text  # noqa: E402
from linuxguardian_ui.scripts import run_sync_async  # noqa: E402

SEV_LABEL = {"critical": "Critical", "warning": "Warning", "info": "Routine"}
SEV_CSS = {"critical": "omega-critical", "warning": "omega-warning", "info": "omega-dim"}


def _label(text: str, css: str | None = None, *, selectable: bool = False) -> Gtk.Label:
    label = Gtk.Label(label=text, xalign=0, wrap=True, selectable=selectable)
    if css:
        label.add_css_class(css)
    return label


def _who(service: dict) -> str:
    return service.get("friendly") or service.get("process") or "owner not visible"


class ExposurePage(Gtk.Box):
    def __init__(self, toast_overlay: Adw.ToastOverlay) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self._toast_overlay = toast_overlay
        self.set_margin_top(16)
        self.set_margin_bottom(16)
        self.set_margin_start(16)
        self.set_margin_end(16)

        self._meta: dict = {}
        self._services: list[dict] = []
        self._scanning = False

        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.append(toolbar)

        self.scan_btn = Gtk.Button(label="Scan Now")
        self.scan_btn.add_css_class("suggested-action")
        self.scan_btn.connect("clicked", lambda _b: self.scan())
        toolbar.append(self.scan_btn)

        copy_btn = Gtk.Button(label="Copy All")
        copy_btn.connect("clicked", self._on_copy_all)
        toolbar.append(copy_btn)

        self.spinner = Gtk.Spinner()
        toolbar.append(self.spinner)

        self.append(
            _label(
                "What is listening on this laptop, who can reach it, and whether a firewall stands in the way. "
                "Detection only: LinuxGuardian never closes a port or changes your firewall, and the advice "
                "below is for you to act on.",
                "omega-dim",
            )
        )

        scroller = Gtk.ScrolledWindow(vexpand=True)
        self.append(scroller)
        self.content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        scroller.set_child(self.content)

        self.status_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.content.append(self.status_box)
        self.sections_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.content.append(self.sections_box)

        self.scan()

    # -- scanning -------------------------------------------------------------
    def scan(self) -> None:
        if self._scanning:
            return
        self._scanning = True
        self.scan_btn.set_sensitive(False)
        self.spinner.start()
        run_sync_async("linux_exposure.sh", ["--check", "--json"], self._on_scan_done, timeout=60.0)

    def _on_scan_done(self, code: int, lines: list[str]) -> bool:
        self._scanning = False
        self.scan_btn.set_sensitive(True)
        self.spinner.stop()
        meta: dict = {}
        services: list[dict] = []
        for line in lines:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("type") == "meta":
                meta = row
            elif row.get("type") == "service":
                services.append(row)
        self._meta, self._services = meta, services
        self._render()
        if not meta:
            self._toast_overlay.add_toast(Adw.Toast(title="Couldn't scan for listening services", timeout=3))
        return False

    # -- rendering ------------------------------------------------------------
    def _clear(self, box: Gtk.Box) -> None:
        while (child := box.get_first_child()) is not None:
            box.remove(child)

    def _render(self) -> None:
        self._render_status()
        self._render_sections()

    def _render_status(self) -> None:
        self._clear(self.status_box)
        meta = self._meta
        if not meta:
            self.status_box.append(_label("Couldn't read this machine's network state. Try Scan Now again.", "omega-warning"))
            return
        if not meta.get("ss_ok"):
            self.status_box.append(_label("Couldn't read listening sockets (is the 'ss' tool installed?).", "omega-warning"))

        fw = meta.get("firewall") or {}
        if fw.get("state") == "active" and fw.get("coverage") == "default_deny":
            self.status_box.append(
                _label(f"Firewall: ON ({fw['kind']}). It blocks unsolicited inbound connections by default.", "omega-heading")
            )
            if not fw.get("rules_readable"):
                self.status_box.append(
                    _label(
                        "Individual allow-rules can't be read without root, so a specific port may still be open "
                        "to your network.",
                        "omega-dim",
                    )
                )
        elif fw.get("state") == "active":
            self.status_box.append(_label(f"Firewall: ON ({fw['kind']}). {fw.get('note', '')}", "omega-warning"))
        else:
            self.status_box.append(
                _label(
                    f"Firewall: OFF. {fw.get('note', '')} Consider turning one on and allowing only what you need "
                    "(for example 'sudo ufw enable'). If you use ROS 2 across machines, allow that traffic first.",
                    "omega-critical",
                    selectable=True,
                )
            )

        nets = meta.get("networks") or []
        self.status_box.append(
            _label(
                "Networks this laptop is on: "
                + (", ".join(f"{n['iface']} {n['addr']} ({n['kind']})" for n in nets) or "none"),
                "omega-dim",
            )
        )
        if meta.get("owners_hidden"):
            self.status_box.append(
                _label(
                    f"{meta['owners_hidden']} listener(s) belong to root or another user, so their owner can't be "
                    "named without root.",
                    "omega-dim",
                )
            )

    def _render_sections(self) -> None:
        self._clear(self.sections_box)
        heading = Gtk.Label(label="Reachable from the network", xalign=0)
        heading.add_css_class("omega-heading")
        heading.add_css_class("title-4")
        self.sections_box.append(heading)
        if not self._meta:
            return

        exposed = [s for s in self._services if s["scope"] != "loopback"]
        attention = [s for s in exposed if s["severity"] != "info"]
        routine = [s for s in exposed if s["severity"] == "info"]
        local_only = [s for s in self._services if s["scope"] == "loopback"]

        if attention:
            for service in attention:
                self.sections_box.append(self._build_service(service, expanded=True))
        else:
            self.sections_box.append(_label("Nothing reachable from the network needs your attention.", "omega-heading"))

        if routine:
            self.sections_box.append(
                self._build_list(
                    f"Routine listeners  —  {len(routine)}",
                    "Discovery, VPN and similar traffic. Shown so nothing is hidden, but not a concern on its own.",
                    routine,
                )
            )
        if local_only:
            self.sections_box.append(
                self._build_list(
                    f"Only reachable from this laptop  —  {len(local_only)}",
                    "These listen on the loopback address, so other machines can't connect to them.",
                    local_only,
                )
            )

    def _build_service(self, service: dict, expanded: bool) -> Gtk.Widget:
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        title = Gtk.Label(
            label=f"{service['label']}  —  {service['proto']}/{service['port']}  —  {_who(service)}",
            xalign=0,
            hexpand=True,
        )
        header.append(title)
        badge = Gtk.Label(label=SEV_LABEL[service["severity"]])
        badge.add_css_class(SEV_CSS[service["severity"]])
        header.append(badge)

        expander = Gtk.Expander()
        expander.set_label_widget(header)
        expander.set_expanded(expanded)

        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin_top=8, margin_start=8)
        expander.set_child(inner)
        for reason in service["reasons"]:
            inner.append(_label(reason, "omega-dim"))
        peers = service.get("peers") or []
        inner.append(
            _label(f"Connected right now: {', '.join(peers) if peers else 'nobody'}", "omega-warning" if peers else "omega-dim")
        )
        if service.get("owner_known") and service.get("pid"):
            inner.append(_label(f"Owner: {service.get('friendly') or service['process']} (PID {service['pid']})", "omega-dim"))
        inner.append(_label("If you don't need it:  " + service["advice"], None, selectable=True))
        return expander

    def _build_list(self, title: str, blurb: str, services: list[dict]) -> Gtk.Widget:
        expander = Gtk.Expander(label=title)
        expander.set_expanded(False)
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_top=8, margin_start=8)
        expander.set_child(inner)
        inner.append(_label(blurb, "omega-dim"))
        listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        listbox.add_css_class("omega-card")
        for service in services:
            row = Gtk.Box(
                orientation=Gtk.Orientation.HORIZONTAL, spacing=12,
                margin_top=6, margin_bottom=6, margin_start=10, margin_end=10,
            )
            row.append(Gtk.Label(label=f"{service['proto']}/{service['port']}  {service['label']}", xalign=0, hexpand=True))
            who = Gtk.Label(label=_who(service), xalign=1)
            who.add_css_class("omega-dim")
            row.append(who)
            listbox.append(row)
        inner.append(listbox)
        return expander

    # -- copy -----------------------------------------------------------------
    def _on_copy_all(self, _btn: Gtk.Button) -> None:
        if not self._meta:
            self._toast_overlay.add_toast(Adw.Toast(title="Nothing to copy yet", timeout=2))
            return
        try:
            copy_text(self._as_text())
        except Exception as exc:  # noqa: BLE001
            self._toast_overlay.add_toast(Adw.Toast(title=f"Copy failed: {exc}", timeout=3))
            return
        self._toast_overlay.add_toast(Adw.Toast(title="Exposure report copied", timeout=2))

    def _as_text(self) -> str:
        meta = self._meta
        fw = meta.get("firewall") or {}
        lines = [
            "LinuxGuardian Watchdog — network exposure report",
            "Please explain which of these listeners matter, which are normal for a ROS 2 / robotics laptop, "
            "and what I should check first.",
            f"Firewall: {fw.get('kind')} {fw.get('state')} (coverage: {fw.get('coverage')}). {fw.get('note', '')}",
            "Networks: " + (", ".join(f"{n['iface']} {n['addr']} ({n['kind']})" for n in meta.get("networks", [])) or "none"),
            "",
        ]
        for service in self._services:
            scope = "loopback only" if service["scope"] == "loopback" else "reachable from the network"
            lines.append(
                f"- [{service['severity']}] {service['label']} {service['proto']}/{service['port']} "
                f"({_who(service)}) — {scope}"
            )
            if service["severity"] != "info":
                lines.extend(f"    {r}" for r in service["reasons"])
                lines.append(f"    Connected now: {', '.join(service.get('peers') or []) or 'nobody'}")
        return "\n".join(lines) + "\n"

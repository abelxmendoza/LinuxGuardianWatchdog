"""VPN page: Tailscale and Proton VPN side by side, and whether they are working together.

Read-only. It shows what each VPN is doing, where your traffic really goes, and anything wrong, in words.
Nothing is sent anywhere except when you press "Check my public IP" (one request to Cloudflare's trace page).
"""
from __future__ import annotations

import json

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk, Pango  # noqa: E402

from linuxguardian_ui import scan_history  # noqa: E402,F401  (puts the suite dir on sys.path)
from linuxguardian_ui.clipboard import copy_text  # noqa: E402
from linuxguardian_ui.components import copy_action, widget_report, page_header, section_header  # noqa: E402
from linuxguardian_ui.scripts import run_sync_async  # noqa: E402

CHIP = {"ok": ("Good", "omega-heading"), "attention": ("Fix", "omega-warning"), "info": ("Note", "omega-dim")}


def _label(text: str, css: str | None = None, *, selectable: bool = False) -> Gtk.Label:
    label = Gtk.Label(label=text, xalign=0, wrap=True, selectable=selectable)
    label.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
    if css:
        label.add_css_class(css)
    return label


def where(dev: str, proton_dev: str = "") -> str:
    """A person's name for a network interface."""
    if not dev:
        return "unknown"
    if dev.startswith("tailscale"):
        return "Tailscale"
    if (proton_dev and dev == proton_dev) or dev.startswith(("proton", "pvpn")):
        return "Proton VPN"
    if dev.startswith(("wl", "wlan")):
        return f"Wi-Fi ({dev})"
    if dev.startswith(("en", "eth")):
        return f"cable ({dev})"
    if dev.startswith(("wg", "tun")):
        return f"a VPN tunnel ({dev})"
    return dev


class VpnPage(Gtk.Box):
    def __init__(self, toast_overlay: Adw.ToastOverlay) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self._toast_overlay = toast_overlay
        self._report = ""
        for side in ("top", "bottom", "start", "end"):
            getattr(self, f"set_margin_{side}")(24)
        self.append(page_header("VPN", "Tailscale and Proton VPN: what each is doing, and whether they work well together.", "network-vpn-symbolic"))

        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        bar.add_css_class("process-toolbar")
        self.append(bar)
        self.check_btn = Gtk.Button(label="Run full VPN check")
        self.check_btn.add_css_class("suggested-action")
        self.check_btn.set_tooltip_text("Re-reads everything and also tests whether a Tailscale device answers while the VPNs are up.")
        self.check_btn.connect("clicked", lambda _b: self.refresh(ping=True))
        bar.append(self.check_btn)
        self.ip_btn = Gtk.Button(label="Check my public IP…")
        self.ip_btn.set_tooltip_text("Makes ONE request to Cloudflare's trace page to see which address the internet sees. Only when you click.")
        self.ip_btn.connect("clicked", lambda _b: self.refresh(public_ip=True))
        bar.append(self.ip_btn)
        self.copy_btn = Gtk.Button(label="Copy report")
        self.copy_btn.set_sensitive(False)
        self.copy_btn.connect("clicked", self._copy)
        bar.append(self.copy_btn)
        self.spinner = Gtk.Spinner()
        bar.append(self.spinner)

        self.append(copy_action("Copy All Page Details", lambda: widget_report(self, "VPN status")))

        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.append(scroller)
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        scroller.set_child(body)

        self.verdict = _label("Checking…", "title-4")
        body.append(self.verdict)

        cards = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12, homogeneous=True)
        body.append(cards)
        self.ts_card = self._card("Tailscale")
        self.px_card = self._card("Proton VPN")
        cards.append(self.ts_card[0])
        cards.append(self.px_card[0])

        body.append(section_header("Where your traffic goes"))
        self.path_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.path_card.add_css_class("omega-card")
        body.append(self.path_card)

        body.append(section_header("What the check found"))
        self.findings = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        body.append(self.findings)

        self.extra = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        body.append(self.extra)

        tips = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        tips.add_css_class("guardian-banner")
        body.append(tips)
        tips.append(_label("Using both together", "omega-heading"))
        tips.append(_label("Use Proton for your internet traffic and Tailscale for your own devices. Don't turn on a Tailscale exit node while "
                           "Proton is connected: both want all your traffic and only one can have it. If your Tailscale devices vanish when "
                           "Proton connects, Proton's kill switch or routing is catching Tailscale's 100.x.x.x addresses. The check above says which.",
                           "omega-dim"))
        self.refresh()

    def _card(self, title: str):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.add_css_class("omega-card")
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        dot = Gtk.Label(label="○")
        dot.add_css_class("title-2")
        head.append(dot)
        name = Gtk.Label(label=title, xalign=0, hexpand=True)
        name.add_css_class("update-name")
        head.append(name)
        box.append(head)
        status = _label("…", None)
        box.append(status)
        lines = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.append(lines)
        return box, dot, status, lines

    @staticmethod
    def _clear(box: Gtk.Box) -> None:
        child = box.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            box.remove(child)
            child = nxt

    # ---- data -------------------------------------------------------------------
    def refresh(self, ping: bool = False, public_ip: bool = False) -> None:
        args = ["--json"] + (["--tailscale-ping"] if ping else []) + (["--public-ip"] if public_ip else [])
        self.spinner.start()
        self.verdict.set_label("Checking…")

        def done(code: int, lines: list[str]) -> None:
            self.spinner.stop()
            try:
                r = json.loads("".join(lines))
            except json.JSONDecodeError:
                self.verdict.set_label("Couldn't read VPN status: " + " ".join(lines)[:160])
                return
            self._render(r)

        run_sync_async("vpn_status.py", args, done, timeout=60.0)

    def _set_dot(self, dot: Gtk.Label, on: bool, css_on: str = "omega-heading") -> None:
        for css in ("omega-heading", "omega-dim", "omega-warning"):
            dot.remove_css_class(css)
        dot.set_label("●" if on else "○")
        dot.add_css_class(css_on if on else "omega-dim")

    def _render(self, r: dict) -> None:
        import vpn_status as vs

        self._report = vs.render_text(r)
        self.copy_btn.set_sensitive(True)
        ts, px, net = r["tailscale"], r["proton"], r["network"]

        # --- verdict
        bad = [f for f in r["findings"] if f["level"] == "attention"]
        self.verdict.set_label("Both VPNs look healthy." if not bad and ts.get("state") == "Running" and px.get("connected")
                               else ("No problems found." if not bad else f"{len(bad)} thing{'s' if len(bad) != 1 else ''} to look at."))
        for css in ("omega-heading", "omega-warning"):
            self.verdict.remove_css_class(css)
        self.verdict.add_css_class("omega-warning" if bad else "omega-heading")

        # --- Tailscale card
        _box, dot, status, lines = self.ts_card
        self._clear(lines)
        ts_on = ts.get("state") == "Running" and ts.get("online")
        self._set_dot(dot, bool(ts_on))
        if not ts.get("installed"):
            status.set_label("Not installed.")
        elif ts_on:
            status.set_label("Connected")
            lines.append(_label(f"Network: {ts.get('tailnet') or 'your tailnet'}", "omega-dim"))
            lines.append(_label(f"Devices online: {ts.get('peers_online', 0)} of {ts.get('peers_total', 0)}", "omega-dim"))
            if ts.get("ips"):
                lines.append(_label("This laptop: " + ", ".join(ts["ips"][:2]), "omega-dim", selectable=True))
            lines.append(_label("Exit node: " + ("ON (all internet traffic goes through another device)" if ts.get("exit_node") else "off"),
                                "omega-warning" if ts.get("exit_node") else "omega-dim"))
        else:
            status.set_label({"NeedsLogin": "Needs you to sign in", "Stopped": "Turned off"}.get(ts.get("state", ""), f"Not connected ({ts.get('state', 'unknown')})"))
            lines.append(_label("To connect: sudo tailscale up", "omega-dim", selectable=True))

        # --- Proton card
        _box, dot, status, lines = self.px_card
        self._clear(lines)
        self._set_dot(dot, bool(px.get("connected")))
        if not px.get("installed"):
            status.set_label("Not detected on this laptop.")
            lines.append(_label("Proton is recognised through NetworkManager or its network device (proton0). If you use it through a "
                                "browser extension or on another device, it can't be seen from here. It shows up automatically once connected.", "omega-dim"))
        elif px.get("connected"):
            status.set_label("Connected")
            lines.append(_label(f"Server: {px.get('connection', '')}", "omega-dim"))
            lines.append(_label(f"Network device: {px.get('device', '')}", "omega-dim"))
        else:
            status.set_label("Installed, not connected")
        if px.get("installed"):
            lines.append(_label("Kill switch: " + ("armed" if px.get("killswitch_present") else "off"),
                                "omega-warning" if px.get("killswitch_present") and not px.get("connected") else "omega-dim"))

        # --- traffic path
        self._clear(self.path_card)
        pdev = px.get("device", "")
        rows = [("Your internet traffic", where(net.get("internet_route_dev", ""), pdev)),
                ("Your Tailscale devices", where(net.get("tailscale_route_dev", ""), pdev) if net.get("tailscale_route_dev") else "(Tailscale off)"),
                ("DNS lookups (website names)", where(net.get("dns_owner", ""), pdev)),
                ("IPv6 internet traffic", where(net.get("ipv6_default_dev", ""), pdev) if net.get("ipv6_default_dev") else "not in use")]
        for name, value in rows:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            n = Gtk.Label(label=name, xalign=0, width_chars=28)
            n.add_css_class("omega-dim")
            row.append(n)
            row.append(Gtk.Label(label="→  " + value, xalign=0))
            self.path_card.append(row)

        # --- findings
        self._clear(self.findings)
        for f in sorted(r["findings"], key=lambda f: {"attention": 0, "info": 2, "ok": 1}[f["level"]]):
            text, css = CHIP[f["level"]]
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            row.add_css_class("omega-card")
            chip = Gtk.Label(label=text, valign=Gtk.Align.START)
            chip.add_css_class("impact-badge")
            chip.add_css_class(css)
            row.append(chip)
            col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
            col.append(_label(f["title"]))
            if f.get("detail"):
                col.append(_label(f["detail"], "omega-dim"))
            if f.get("advice") and f["level"] == "attention":
                col.append(_label("What to do: " + f["advice"], "omega-warning", selectable=True))
            row.append(col)
            self.findings.append(row)

        # --- optional probes
        self._clear(self.extra)
        if "tailscale_ping" in r:
            pg = r["tailscale_ping"]
            self.extra.append(_label(("Reached a Tailscale device: " if pg["ok"] else "Couldn't reach a Tailscale device: ") + pg["detail"],
                                     "omega-heading" if pg["ok"] else "omega-warning"))
        if "public_ip" in r:
            p = r["public_ip"]
            if p.get("ip"):
                self.extra.append(_label(f"The internet sees you as {p['ip']}" + (f" ({p['loc']})" if p.get("loc") else ""), "omega-heading", selectable=True))
                if px.get("connected"):
                    self.extra.append(_label("With Proton connected this should be a Proton server in the country you chose, not your home address.", "omega-dim"))
            else:
                self.extra.append(_label(f"Couldn't check: {p.get('error', 'no answer')}", "omega-warning"))

    def _copy(self, _btn: Gtk.Button) -> None:
        try:
            copy_text(self._report)
            self._toast_overlay.add_toast(Adw.Toast.new("VPN report copied"))
        except Exception as exc:  # noqa: BLE001
            self._toast_overlay.add_toast(Adw.Toast.new(f"Copy failed: {exc}"))

"""Main application window: sidebar + view stack, libadwaita-style."""
from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk  # noqa: E402

from linuxguardian_ui.components import LOGO_FULL, brand_lockup  # noqa: E402

from linuxguardian_ui.pages.apps import AppsPage  # noqa: E402
from linuxguardian_ui.components import report_window, widget_report
from linuxguardian_ui.reports import export_session, export_saved_scan, timestamp
from linuxguardian_ui.scan_history import load_last_scan

from linuxguardian_ui.pages.cache_cleaner import CacheCleanerPage  # noqa: E402
from linuxguardian_ui.pages.dashboard import DashboardPage  # noqa: E402
from linuxguardian_ui.pages.exposure import ExposurePage  # noqa: E402
from linuxguardian_ui.pages.firewall import FirewallPage  # noqa: E402
from linuxguardian_ui.pages.hardening import HardeningPage  # noqa: E402
from linuxguardian_ui.pages.processes import ProcessesPage  # noqa: E402
from linuxguardian_ui import crashlog  # noqa: E402
from linuxguardian_ui.pages.health_window import HealthWindow  # noqa: E402
from linuxguardian_ui.pages.incidents import InvestigatePage  # noqa: E402
from linuxguardian_ui.pages.malware import MalwarePage  # noqa: E402
from linuxguardian_ui.pages.terminal_window import TerminalWindow  # noqa: E402
from linuxguardian_ui.pages.updates import UpdatesPage  # noqa: E402
from linuxguardian_ui.pages.vpn import VpnPage  # noqa: E402


# What the terminal-commands window is pre-filtered to for each tab, so the button opens the commands for the feature you are looking at.
TAB_FOCUS = {"dashboard": "scan", "hardening": "hardening", "vpn": "vpn", "processes": "process", "cache": "cache", "updates": "updates",
             "exposure": "listening", "firewall": "firewall", "incidents": "incidents", "malware": "quarantine"}


class LinuxGuardianWindow(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application) -> None:
        super().__init__(application=app, title="LinuxGuardian Watchdog")
        self.set_default_size(1280, 800)

        # Adw.ToolbarView needs libadwaita >= 1.4; build the header + content
        # layout by hand instead so this also runs on 1.1-1.3 (e.g. Ubuntu 22.04).
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_content(root)

        header = Adw.HeaderBar()
        root.append(header)

        header.pack_start(brand_lockup())

        # Two always-available escape hatches that don't depend on any tab working.
        term_btn = Gtk.Button(icon_name="utilities-terminal-symbolic")
        term_btn.add_css_class("flat")
        term_btn.set_tooltip_text("Terminal commands: run this tab's feature (or any other) by hand if the app misbehaves")
        term_btn.connect("clicked", lambda _b: self.open_terminal_commands(TAB_FOCUS.get(self.view_stack.get_visible_child_name())))
        header.pack_end(term_btn)

        self.health_btn = Gtk.Button(icon_name="emblem-ok-symbolic")
        self.health_btn.add_css_class("flat")
        self.health_btn.set_tooltip_text("LinuxGuardian health: is the app itself intact and still watching?")
        self.health_btn.connect("clicked", lambda _b: self.open_health())
        header.pack_end(self.health_btn)

        about_btn = Gtk.Button(icon_name="help-about-symbolic")
        about_btn.add_css_class("flat")
        about_btn.set_tooltip_text("About LinuxGuardian Watchdog")
        about_btn.connect("clicked", self._show_about)
        header.pack_end(about_btn)

        view_switcher = Adw.ViewSwitcher()
        header.set_title_widget(view_switcher)

        # ToastOverlay wraps the content area so any page can pop a toast
        # (e.g. "Process killed", "Cache cleanup complete").
        self.toast_overlay = Adw.ToastOverlay(vexpand=True)
        root.append(self.toast_overlay)

        stack = Adw.ViewStack(vexpand=True)
        self.view_stack = stack                  # pages (e.g. the Dashboard's Hardening card) switch tabs through this
        view_switcher.set_stack(stack)
        self.toast_overlay.set_child(stack)
        report_btn = Gtk.Button(icon_name="edit-copy-symbolic")
        report_btn.set_tooltip_text("Security report: view and copy all captured page summaries and technical output")
        def show_report(_button):
            sections = ["LinuxGuardian — security posture & diagnostics", f"Exported: {timestamp()}",
                        "Scope: current page snapshots and captured session output. This does not run new checks.",
                        "Includes local paths, commands, and network details; review before sharing."]
            for page in stack.get_pages():
                child = page.get_child()
                sections.append(widget_report(child, page.get_title()))
                if hasattr(child, "_reports"):
                    sections.append(export_session(child._reports))
                if page.get_name() == "processes":
                    sections.append(child._technical_report())
                elif page.get_name() == "updates":
                    sections.append(child._list_as_text())
                elif page.get_name() == "cache":
                    sections.append(child._list_as_text())
            sections.append(export_saved_scan(load_last_scan()))
            report_window(self, "Security posture & diagnostics", "\n\n".join(sections))
        report_btn.connect("clicked", show_report)
        header.pack_end(report_btn)

        dashboard_page = stack.add_titled(self._safe(lambda: DashboardPage(), "Dashboard"), "dashboard", "Dashboard")
        dashboard_page.set_icon_name("security-high-symbolic")

        hardening_page = stack.add_titled(self._safe(lambda: HardeningPage(self.toast_overlay), "Hardening"), "hardening", "Hardening")
        hardening_page.set_icon_name("security-medium-symbolic")

        vpn_page = stack.add_titled(self._safe(lambda: VpnPage(self.toast_overlay), "VPN"), "vpn", "VPN")
        vpn_page.set_icon_name("network-vpn-symbolic")

        processes_page = stack.add_titled(
            self._safe(lambda: ProcessesPage(self.toast_overlay), "Processes"), "processes", "Processes"
        )
        processes_page.set_icon_name("system-run-symbolic")

        cache_page = stack.add_titled(
            self._safe(lambda: CacheCleanerPage(self.toast_overlay), "Cache Cleaner"), "cache", "Cleaner"
        )
        cache_page.set_icon_name("user-trash-symbolic")

        updates_page = stack.add_titled(
            self._safe(lambda: UpdatesPage(self.toast_overlay), "Updates"), "updates", "Updates"
        )
        updates_page.set_icon_name("software-update-available-symbolic")

        exposure_page = stack.add_titled(
            self._safe(lambda: ExposurePage(self.toast_overlay), "Exposure"), "exposure", "Exposure"
        )
        exposure_page.set_icon_name("network-wired-symbolic")

        firewall_page = stack.add_titled(
            self._safe(lambda: FirewallPage(self.toast_overlay, lambda: stack.set_visible_child_name("exposure")), "Firewall"),
            "firewall", "Firewall",
        )
        firewall_page.set_icon_name("channel-secure-symbolic")

        apps_page = stack.add_titled(self._safe(lambda: AppsPage(self.toast_overlay), "Apps"), "apps", "Apps")
        apps_page.set_icon_name("folder-download-symbolic")

        incidents_page = stack.add_titled(self._safe(lambda: InvestigatePage(self.toast_overlay), "Incidents"), "incidents", "Incidents")
        incidents_page.set_icon_name("dialog-warning-symbolic")

        malware_page = stack.add_titled(self._safe(lambda: MalwarePage(self.toast_overlay, self.open_terminal_commands), "Malware"), "malware", "Malware")
        malware_page.set_icon_name("security-low-symbolic")
        # Future pages: settings — see docs/ROADMAP.md

        GLib.timeout_add_seconds(3, self._startup_health_check)      # after the window is up, so it never delays opening

    # ---- resilience ---------------------------------------------------------
    def _safe(self, factory, title: str) -> Gtk.Widget:
        """Build one tab. If it can't be built, show what happened (and how to carry on by hand) instead of taking the whole app down."""
        try:
            return factory()
        except Exception as exc:  # noqa: BLE001 - this is the safety net
            summary = crashlog.record(f"building the {title} tab", exc)
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=32, margin_bottom=32, margin_start=32, margin_end=32, valign=Gtk.Align.START)
            head = Gtk.Label(label=f"The {title} tab couldn't load", xalign=0)
            head.add_css_class("title-2")
            head.add_css_class("omega-critical")
            box.append(head)
            for text in ("The rest of the app still works. This was written to ~/.linuxguardian/logs/app-errors.log.", summary):
                lab = Gtk.Label(label=text, xalign=0, wrap=True, selectable=True)
                lab.add_css_class("omega-dim")
                box.append(lab)
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, halign=Gtk.Align.START)
            box.append(row)
            term = Gtk.Button(label="Use the terminal commands instead")
            term.add_css_class("suggested-action")
            term.connect("clicked", lambda _b: self.open_terminal_commands())
            row.append(term)
            health = Gtk.Button(label="Check LinuxGuardian's health")
            health.connect("clicked", lambda _b: self.open_health())
            row.append(health)
            return box

    def open_terminal_commands(self, focus: str | None = None) -> None:
        TerminalWindow(self, self.toast_overlay, focus=focus).present()

    def open_health(self) -> None:
        HealthWindow(self, self.toast_overlay, on_result=self._health_result, open_terminal=self.open_terminal_commands).present()

    def _health_result(self, r: dict) -> None:
        for css in ("success", "warning", "error"):
            self.health_btn.remove_css_class(css)
        level = r.get("level")
        self.health_btn.add_css_class("error" if level == "critical" else "warning" if level == "warning" else "success")
        self.health_btn.set_tooltip_text(f"LinuxGuardian health: {r.get('headline', '')}")

    def _startup_health_check(self) -> bool:
        from linuxguardian_ui.scripts import run_sync_async
        import json

        def done(code: int, lines: list[str]) -> None:
            try:
                r = json.loads("".join(lines))
            except ValueError:
                return
            self._health_result(r)
            if r.get("level") in ("warning", "critical"):
                self.toast_overlay.add_toast(Adw.Toast.new(r["headline"] + " Click the check-mark in the title bar."))

        run_sync_async("self_check.py", ["--check", "--json"], done, timeout=60.0)
        return False

    def _show_about(self, _btn: Gtk.Button) -> None:
        about = Gtk.AboutDialog(transient_for=self, modal=True)
        about.set_program_name("LinuxGuardian Watchdog")
        about.set_comment("A native Linux security suite: scans, updates, exposure and process control, all local.")
        about.set_license_type(Gtk.License.MIT_X11)
        about.set_website("https://github.com/abelxmendoza/LinuxGuardianWatchdog")
        try:
            about.set_logo(Gdk.Texture.new_from_filename(str(LOGO_FULL)))
        except Exception:  # noqa: BLE001 - a missing logo must not break About
            about.set_logo_icon_name("linuxguardian-watchdog")
        about.present()

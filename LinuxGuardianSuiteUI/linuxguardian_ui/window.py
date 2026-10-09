"""Main application window: sidebar + view stack, libadwaita-style."""
from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gtk  # noqa: E402

from linuxguardian_ui.components import LOGO_FULL, brand_lockup  # noqa: E402

from linuxguardian_ui.pages.cache_cleaner import CacheCleanerPage  # noqa: E402
from linuxguardian_ui.pages.dashboard import DashboardPage  # noqa: E402
from linuxguardian_ui.pages.exposure import ExposurePage  # noqa: E402
from linuxguardian_ui.pages.processes import ProcessesPage  # noqa: E402
from linuxguardian_ui.pages.timeline import TimelinePage  # noqa: E402
from linuxguardian_ui.pages.updates import UpdatesPage  # noqa: E402


class LinuxGuardianWindow(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application) -> None:
        super().__init__(application=app, title="LinuxGuardian Watchdog")
        self.set_default_size(1000, 720)

        # Adw.ToolbarView needs libadwaita >= 1.4; build the header + content
        # layout by hand instead so this also runs on 1.1-1.3 (e.g. Ubuntu 22.04).
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_content(root)

        header = Adw.HeaderBar()
        root.append(header)

        header.pack_start(brand_lockup())

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
        view_switcher.set_stack(stack)
        self.toast_overlay.set_child(stack)

        dashboard_page = stack.add_titled(DashboardPage(), "dashboard", "Dashboard")
        dashboard_page.set_icon_name("security-high-symbolic")

        processes_page = stack.add_titled(
            ProcessesPage(self.toast_overlay), "processes", "Processes"
        )
        processes_page.set_icon_name("system-run-symbolic")

        cache_page = stack.add_titled(
            CacheCleanerPage(self.toast_overlay), "cache", "Cache Cleaner"
        )
        cache_page.set_icon_name("user-trash-symbolic")

        updates_page = stack.add_titled(
            UpdatesPage(self.toast_overlay), "updates", "Updates"
        )
        updates_page.set_icon_name("software-update-available-symbolic")

        exposure_page = stack.add_titled(
            ExposurePage(self.toast_overlay), "exposure", "Exposure"
        )
        exposure_page.set_icon_name("network-wired-symbolic")

        timeline_page = stack.add_titled(TimelinePage(self.toast_overlay), "timeline", "Timeline")
        timeline_page.set_icon_name("document-open-recent-symbolic")
        # Future pages: settings — see docs/ROADMAP.md

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

"""Main application window: sidebar + view stack, libadwaita-style."""
from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

from linuxguardian_ui.pages.cache_cleaner import CacheCleanerPage  # noqa: E402
from linuxguardian_ui.pages.dashboard import DashboardPage  # noqa: E402
from linuxguardian_ui.pages.processes import ProcessesPage  # noqa: E402


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

        # "Ω" — the original theme's prompt glyph (theme_omega_black_ops.sh).
        omega_label = Gtk.Label(label="Ω")
        omega_label.add_css_class("omega-heading")
        omega_label.add_css_class("title-2")
        header.pack_start(omega_label)

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
        # Future pages: incidents history, settings — see docs/ROADMAP.md

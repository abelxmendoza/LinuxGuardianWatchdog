"""Main application window: sidebar + view stack, libadwaita-style."""
from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

from linuxguardian_ui.pages.dashboard import DashboardPage  # noqa: E402


class LinuxGuardianWindow(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application) -> None:
        super().__init__(application=app, title="LinuxGuardian Watchdog")
        self.set_default_size(900, 600)

        toolbar_view = Adw.ToolbarView()
        self.set_content(toolbar_view)

        header = Adw.HeaderBar()
        toolbar_view.add_top_bar(header)

        view_switcher = Adw.ViewSwitcher()
        header.set_title_widget(view_switcher)

        stack = Adw.ViewStack()
        view_switcher.set_stack(stack)
        toolbar_view.set_content(stack)

        stack.add_titled_with_icon(
            DashboardPage(), "dashboard", "Dashboard", "security-high-symbolic"
        )
        # Future pages: incidents history, settings — see docs/ROADMAP.md

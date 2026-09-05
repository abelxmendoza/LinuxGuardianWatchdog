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

        # Adw.ToolbarView needs libadwaita >= 1.4; build the header + content
        # layout by hand instead so this also runs on 1.1-1.3 (e.g. Ubuntu 22.04).
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_content(root)

        header = Adw.HeaderBar()
        root.append(header)

        view_switcher = Adw.ViewSwitcher()
        header.set_title_widget(view_switcher)

        stack = Adw.ViewStack(vexpand=True)
        view_switcher.set_stack(stack)
        root.append(stack)

        page = stack.add_titled(DashboardPage(), "dashboard", "Dashboard")
        page.set_icon_name("security-high-symbolic")
        # Future pages: incidents history, settings — see docs/ROADMAP.md

"""Entry point: `python3 -m linuxguardian_ui.main`."""
from __future__ import annotations

import sys
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gtk  # noqa: E402

from linuxguardian_ui.window import LinuxGuardianWindow  # noqa: E402

APP_ID = "org.linuxguardian.Watchdog"
STYLE_CSS = Path(__file__).resolve().parents[1] / "resources" / "style.css"


def _load_omega_theme() -> None:
    """Apply the "Omega Black-Ops" theme, ported from MacGuardianWatchdog."""
    Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    provider = Gtk.CssProvider()
    provider.load_from_path(str(STYLE_CSS))
    Gtk.StyleContext.add_provider_for_display(
        Gdk.Display.get_default(),
        provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
    )


def main() -> int:
    app = Adw.Application(application_id=APP_ID)

    def on_activate(app: Adw.Application) -> None:
        _load_omega_theme()
        win = LinuxGuardianWindow(app)
        win.present()

    app.connect("activate", on_activate)
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())

"""Entry point: `python3 -m linuxguardian_ui.main`."""
from __future__ import annotations

import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw  # noqa: E402

from linuxguardian_ui.window import LinuxGuardianWindow  # noqa: E402

APP_ID = "org.linuxguardian.Watchdog"


def main() -> int:
    app = Adw.Application(application_id=APP_ID)

    def on_activate(app: Adw.Application) -> None:
        win = LinuxGuardianWindow(app)
        win.present()

    app.connect("activate", on_activate)
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())

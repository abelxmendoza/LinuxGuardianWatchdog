"""Standalone live-progress window that attaches to an already-running scan.

Uses a different application id so it can open beside an older Watchdog
window that was started before progress existed.
"""
from __future__ import annotations

import sys
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk, Pango  # noqa: E402

from linuxguardian_ui.live_scan import (  # noqa: E402
    RunningScan,
    find_running_scan,
    human_bytes,
    snapshot,
)
from linuxguardian_ui.progress import format_duration, phase_label  # noqa: E402

APP_ID = "org.linuxguardian.Watchdog.ScanWatch"
STYLE_CSS = Path(__file__).resolve().parents[1] / "resources" / "style.css"


def _load_theme() -> None:
    Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    provider = Gtk.CssProvider()
    provider.load_from_path(str(STYLE_CSS))
    Gtk.StyleContext.add_provider_for_display(
        Gdk.Display.get_default(),
        provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
    )


class ScanWatchWindow(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application) -> None:
        super().__init__(application=app, title="LinuxGuardian — Scan Progress")
        self.set_default_size(640, 280)
        self.set_resizable(True)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_content(root)

        header = Adw.HeaderBar()
        root.append(header)
        omega = Gtk.Label(label="Ω")
        omega.add_css_class("omega-heading")
        omega.add_css_class("title-2")
        header.pack_start(omega)
        header.set_title_widget(Gtk.Label(label="Live scan progress"))

        body = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=10,
            margin_top=16,
            margin_bottom=16,
            margin_start=16,
            margin_end=16,
        )
        root.append(body)

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        card.add_css_class("omega-card")
        body.append(card)

        heading = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        card.append(heading)
        self.spinner = Gtk.Spinner()
        heading.append(self.spinner)
        self.title_label = Gtk.Label(label="Looking for a running scan…", xalign=0, hexpand=True)
        self.title_label.add_css_class("omega-heading")
        self.title_label.add_css_class("title-3")
        heading.append(self.title_label)

        self.subtitle = Gtk.Label(label="", xalign=0, wrap=True)
        card.append(self.subtitle)

        self.bar = Gtk.ProgressBar(show_text=True, hexpand=True)
        self.bar.set_pulse_step(0.08)
        card.append(self.bar)

        times = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        card.append(times)
        self.elapsed_label = Gtk.Label(label="", xalign=0, hexpand=True)
        times.append(self.elapsed_label)
        self.detail_label = Gtk.Label(label="", xalign=1, hexpand=True)
        self.detail_label.add_css_class("omega-warning")
        times.append(self.detail_label)

        self.current_label = Gtk.Label(label="", xalign=0, hexpand=True)
        self.current_label.add_css_class("omega-dim")
        self.current_label.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
        card.append(self.current_label)

        note = Gtk.Label(
            label="This window watches the scan already in progress. "
            "The original Watchdog window stays silent because that session "
            "started before live progress existed. Leave both open.",
            xalign=0,
            wrap=True,
        )
        note.add_css_class("omega-dim")
        body.append(note)

        self._scan: RunningScan | None = find_running_scan()
        self.spinner.start()
        GLib.timeout_add(400, self._tick)
        self._tick()

    def _tick(self) -> bool:
        if self._scan is None:
            self._scan = find_running_scan()
        if self._scan is None:
            self.spinner.stop()
            self.title_label.set_label("No scan running")
            self.subtitle.set_label("Start a malware/rootkit scan in LinuxGuardian, then this window will attach.")
            self.bar.set_fraction(0)
            self.bar.set_text("Idle")
            self.elapsed_label.set_label("")
            self.detail_label.set_label("")
            self.current_label.set_label("")
            return True
        snap = snapshot(self._scan)
        if not snap.alive:
            self.spinner.stop()
            self.title_label.set_label("Scan finished")
            self.subtitle.set_label("The scanner process exited. Check the main Watchdog window or ~/.linuxguardian/logs/scans/.")
            self.bar.set_fraction(1.0)
            self.bar.set_text("Done")
            self.detail_label.set_label("Completed")
            return True
        self.spinner.start()
        self.title_label.set_label(f"{phase_label(snap.phase)} in progress")
        self.subtitle.set_label(
            f"PID {snap.pid} · {snap.comm} · target {snap.target} · "
            "still running (not frozen)"
        )
        self.bar.pulse()
        self.bar.set_text("Working…")
        self.elapsed_label.set_label(f"Elapsed {format_duration(snap.elapsed_sec)}")
        read = f"{human_bytes(snap.bytes_read)} read" if snap.bytes_read else "reading files"
        self.detail_label.set_label(f"{read} · CPU {snap.cpu_pct}")
        if snap.current:
            self.current_label.set_label(f"Current: {snap.current}")
        self.set_title(f"LinuxGuardian — scanning {format_duration(snap.elapsed_sec)}")
        return True


def main() -> int:
    app = Adw.Application(application_id=APP_ID)

    def on_activate(app: Adw.Application) -> None:
        _load_theme()
        win = ScanWatchWindow(app)
        win.present()

    app.connect("activate", on_activate)
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())

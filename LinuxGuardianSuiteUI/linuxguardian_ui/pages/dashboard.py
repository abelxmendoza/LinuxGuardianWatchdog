"""Dashboard page: run scans and watch live output."""
from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

from linuxguardian_ui.scripts import run_streaming_async  # noqa: E402


class DashboardPage(Gtk.Box):
    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_margin_top(16)
        self.set_margin_bottom(16)
        self.set_margin_start(16)
        self.set_margin_end(16)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.append(actions)

        self.scan_btn = Gtk.Button(label="Run Malware/Rootkit Scan")
        self.scan_btn.add_css_class("suggested-action")
        self.scan_btn.connect("clicked", self._on_scan_clicked)
        actions.append(self.scan_btn)

        self.integrity_btn = Gtk.Button(label="Check File Integrity")
        self.integrity_btn.connect("clicked", self._on_integrity_clicked)
        actions.append(self.integrity_btn)

        self.audit_btn = Gtk.Button(label="Run Security Audit")
        self.audit_btn.connect("clicked", self._on_audit_clicked)
        actions.append(self.audit_btn)

        self.spinner = Gtk.Spinner()
        actions.append(self.spinner)

        scroller = Gtk.ScrolledWindow(vexpand=True)
        self.append(scroller)

        self.output_view = Gtk.TextView(editable=False, monospace=True)
        self.output_view.add_css_class("card")
        scroller.set_child(self.output_view)
        self.buffer = self.output_view.get_buffer()

    def _set_busy(self, busy: bool) -> None:
        for btn in (self.scan_btn, self.integrity_btn, self.audit_btn):
            btn.set_sensitive(not busy)
        if busy:
            self.spinner.start()
        else:
            self.spinner.stop()

    def _append_line(self, line: str) -> bool:
        end = self.buffer.get_end_iter()
        self.buffer.insert(end, line + "\n")
        return False

    def _clear(self) -> None:
        self.buffer.set_text("")

    def _run(self, script: str, args: list[str], label: str) -> None:
        self._clear()
        self._append_line(f"$ {script} {' '.join(args)}")
        self._set_busy(True)

        def on_done(code: int) -> bool:
            self._append_line(f"\n[{label} finished, exit code {code}]")
            self._set_busy(False)
            return False

        run_streaming_async(script, args, self._append_line, on_done)

    def _on_scan_clicked(self, _btn: Gtk.Button) -> None:
        self._run("linux_guardian.sh", ["--scan"], "Scan")

    def _on_integrity_clicked(self, _btn: Gtk.Button) -> None:
        self._run("linux_watchdog.sh", ["--check"], "Integrity check")

    def _on_audit_clicked(self, _btn: Gtk.Button) -> None:
        self._run("linux_security_audit.sh", [], "Security audit")

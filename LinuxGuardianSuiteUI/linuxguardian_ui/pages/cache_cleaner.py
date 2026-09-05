"""Cache Cleaner page — browser + system cache cleanup with size preview,
mirroring the macOS original's Cache Cleaner feature."""
from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

from linuxguardian_ui.dialogs import confirm  # noqa: E402
from linuxguardian_ui.scripts import run_sync_async  # noqa: E402


class CacheCleanerPage(Gtk.Box):
    def __init__(self, toast_overlay: Adw.ToastOverlay) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self._toast_overlay = toast_overlay
        self.set_margin_top(16)
        self.set_margin_bottom(16)
        self.set_margin_start(16)
        self.set_margin_end(16)

        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.append(toolbar)

        rescan_btn = Gtk.Button(label="Rescan")
        rescan_btn.connect("clicked", lambda _b: self.rescan())
        toolbar.append(rescan_btn)

        self.clean_btn = Gtk.Button(label="Clear All Caches")
        self.clean_btn.add_css_class("destructive-action")
        self.clean_btn.connect("clicked", self._on_clean_clicked)
        toolbar.append(self.clean_btn)

        self.spinner = Gtk.Spinner()
        toolbar.append(self.spinner)

        scroller = Gtk.ScrolledWindow(vexpand=True)
        self.append(scroller)

        self.output_view = Gtk.TextView(editable=False, monospace=True)
        self.output_view.add_css_class("omega-card")
        scroller.set_child(self.output_view)
        self.buffer = self.output_view.get_buffer()

        self.rescan()

    def _set_busy(self, busy: bool) -> None:
        self.clean_btn.set_sensitive(not busy)
        if busy:
            self.spinner.start()
        else:
            self.spinner.stop()

    def rescan(self) -> None:
        self._set_busy(True)
        self.buffer.set_text("Scanning caches...")
        run_sync_async("linux_cache_cleanup.sh", ["--scan"], self._on_scan_done, timeout=60.0)

    def _on_scan_done(self, code: int, lines: list[str]) -> bool:
        self._set_busy(False)
        self.buffer.set_text("\n".join(lines) if lines else "No cache data found.")
        return False

    def _on_clean_clicked(self, _btn: Gtk.Button) -> None:
        root = self.get_root()
        confirm(
            root,
            "Clear all caches?",
            "This deletes browser and system cache files shown in the scan. "
            "It does not touch bookmarks, history, passwords, or documents.",
            confirm_label="Clear Caches",
            on_confirm=self._do_clean,
        )

    def _do_clean(self) -> None:
        self._set_busy(True)
        self.buffer.set_text("Clearing caches...")

        def on_done(code: int, lines: list[str]) -> bool:
            self._set_busy(False)
            self.buffer.set_text("\n".join(lines))
            message = "Cache cleanup complete" if code == 0 else "Cache cleanup failed"
            self._toast_overlay.add_toast(Adw.Toast(title=message, timeout=3))
            return False

        run_sync_async("linux_cache_cleanup.sh", ["--clean", "--apply"], on_done, timeout=300.0)

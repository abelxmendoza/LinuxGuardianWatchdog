"""Cache Cleaner page — browser + system cache cleanup with a size preview.

Rather than one all-or-nothing "clear everything" button, caches are split
into named categories you can pick from individually, each with a plain
description of what it is and what clearing it costs you (nothing but a
slightly slower next app launch, in every case here).
"""
from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

from linuxguardian_ui.components import page_header, info_banner
from linuxguardian_ui.clipboard import copy_text  # noqa: E402
from linuxguardian_ui.dialogs import confirm  # noqa: E402
from linuxguardian_ui.scripts import run_sync_async  # noqa: E402

CATEGORY_INFO = {
    "browser": (
        "Web Browser Caches",
        "Cached pages, images, and scripts from Firefox/Chrome/Chromium/Brave. "
        "Safe to clear — sites just reload assets on your next visit.",
    ),
    "thumbnails": (
        "Thumbnail Cache",
        "Preview images for your files and photos. Safe to clear — thumbnails "
        "regenerate automatically as you browse folders.",
    ),
    "app_cache": (
        "Other Application Caches",
        "Cached data from your other apps (build tools, editors, indexers, etc.). "
        "Safe to clear — apps rebuild what they need, though a couple may be "
        "slightly slower the next time they start.",
    ),
}
CATEGORY_ORDER = ["browser", "thumbnails", "app_cache"]


def human(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


class CacheCleanerPage(Gtk.Box):
    def __init__(self, toast_overlay: Adw.ToastOverlay) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self._toast_overlay = toast_overlay
        self.set_margin_top(24)
        self.set_margin_bottom(24)
        self.set_margin_start(24)
        self.set_margin_end(24)

        self.append(page_header("Cache cleaner", "Review reclaimable space before clearing selected categories.", "user-trash-symbolic"))

        self.append(info_banner("These are temporary files your apps rebuild automatically. Clearing them is safe — apps may take a few extra seconds to start up the first time after clearing."))

        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        toolbar.add_css_class("process-toolbar")
        self.append(toolbar)

        rescan_btn = Gtk.Button(label="Rescan")
        rescan_btn.connect("clicked", lambda _b: self.rescan())
        toolbar.append(rescan_btn)

        self.clean_btn = Gtk.Button(label="Clear Selected")
        self.clean_btn.add_css_class("destructive-action")
        self.clean_btn.connect("clicked", self._on_clean_clicked)
        toolbar.append(self.clean_btn)

        copy_btn = Gtk.Button(label="Copy All")
        copy_btn.connect("clicked", self._on_copy_all)
        toolbar.append(copy_btn)

        self.spinner = Gtk.Spinner()
        toolbar.append(self.spinner)

        total_card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        total_card.add_css_class("omega-card")
        self.total_label = Gtk.Label(xalign=0, hexpand=True)
        self.total_label.add_css_class("omega-heading")
        self.total_label.add_css_class("title-3")
        total_card.append(self.total_label)
        self.append(total_card)

        scroller = Gtk.ScrolledWindow(vexpand=True)
        self.append(scroller)

        self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.listbox.add_css_class("omega-card")
        scroller.set_child(self.listbox)

        self._checkboxes: dict[str, Gtk.CheckButton] = {}
        self._category_bytes: dict[str, int] = {}
        self._category_paths: dict[str, list[tuple[int, str]]] = {}
        self._scanned = False

        self.rescan()

    def _set_busy(self, busy: bool) -> None:
        self.clean_btn.set_sensitive(not busy)
        if busy:
            self.spinner.start()
        else:
            self.spinner.stop()

    def rescan(self) -> None:
        self._set_busy(True)
        self.total_label.set_label("Scanning...")
        run_sync_async("linux_cache_cleanup.sh", ["--scan"], self._on_scan_done, timeout=60.0)

    def _on_scan_done(self, code: int, lines: list[str]) -> bool:
        self._set_busy(False)
        self._scanned = True
        self._category_bytes = {}
        self._category_paths = {}
        for line in lines:
            parts = line.split("|")
            if len(parts) != 4:
                continue
            category, size_bytes, _human, path = parts
            try:
                size_bytes = int(size_bytes)
            except ValueError:
                continue
            self._category_bytes[category] = self._category_bytes.get(category, 0) + size_bytes
            self._category_paths.setdefault(category, []).append((size_bytes, path))
        self._render()
        return False

    def _render(self) -> None:
        while (child := self.listbox.get_first_child()) is not None:
            self.listbox.remove(child)
        self._checkboxes = {}

        found = False
        for category in CATEGORY_ORDER:
            total = self._category_bytes.get(category, 0)
            if total == 0:
                continue
            found = True
            self.listbox.append(self._build_category_row(category, total))

        if not found and self._scanned:
            empty = Gtk.Label(
                label="Nothing to clear — your cache is already clean.",
                xalign=0,
                wrap=True,
                margin_top=20,
                margin_bottom=20,
                margin_start=14,
            )
            empty.add_css_class("omega-dim")
            self.listbox.append(empty)

        self._update_total()

    def _build_category_row(self, category: str, total: int) -> Gtk.Widget:
        name, description = CATEGORY_INFO[category]
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, margin_top=8, margin_bottom=8, margin_start=10, margin_end=10)

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        outer.append(header)

        check = Gtk.CheckButton(active=True)
        check.connect("toggled", lambda _c: self._update_total())
        self._checkboxes[category] = check
        header.append(check)

        name_label = Gtk.Label(label=f"{name} — {human(total)}", xalign=0, hexpand=True)
        name_label.add_css_class("omega-heading")
        name_label.set_wrap(True)
        header.append(name_label)

        paths = self._category_paths.get(category, [])
        if paths:
            n = len(paths)
            expander = Gtk.Expander(label=f"Show {n} location{'s' if n != 1 else ''}")
            outer.append(expander)
            detail = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, margin_top=4)
            expander.set_child(detail)
            for size_bytes, path in sorted(paths, reverse=True)[:20]:
                line = Gtk.Label(label=f"{human(size_bytes)}   {path}", xalign=0)
                line.add_css_class("omega-dim")
                detail.append(line)

        desc_label = Gtk.Label(label=description, xalign=0, wrap=True)
        desc_label.add_css_class("omega-dim")
        outer.append(desc_label)

        return outer

    def _update_total(self) -> None:
        selected = sum(
            self._category_bytes.get(cat, 0)
            for cat, cb in self._checkboxes.items()
            if cb.get_active()
        )
        grand_total = sum(self._category_bytes.values())
        if grand_total == 0:
            self.total_label.set_label("Nothing to clear" if self._scanned else "—")
        else:
            self.total_label.set_label(f"Selected: {human(selected)} of {human(grand_total)} reclaimable")

    def _selected_categories(self) -> list[str]:
        return [cat for cat, cb in self._checkboxes.items() if cb.get_active()]

    def _on_copy_all(self, _btn: Gtk.Button) -> None:
        if not self._category_bytes:
            self._toast_overlay.add_toast(Adw.Toast(title="Nothing to copy yet", timeout=2))
            return
        try:
            copy_text(self._list_as_text())
        except Exception as exc:  # noqa: BLE001
            self._toast_overlay.add_toast(Adw.Toast(title=f"Copy failed: {exc}", timeout=3))
            return
        self._toast_overlay.add_toast(Adw.Toast(title="Cache list copied", timeout=2))

    def _list_as_text(self) -> str:
        selected = set(self._selected_categories())
        grand = sum(self._category_bytes.values())
        lines = [
            "LinuxGuardian Watchdog — cache cleaner list",
            "Please explain what each cache is, whether it is safe to clear, and what I would lose.",
            "Everything here is regenerable app data, not documents, bookmarks, passwords, or history.",
            f"Total reclaimable: {human(grand)}",
            "",
        ]
        for category in CATEGORY_ORDER:
            total = self._category_bytes.get(category, 0)
            if total == 0:
                continue
            name, description = CATEGORY_INFO[category]
            marked = "selected" if category in selected else "not selected"
            lines.append(f"## {name} — {human(total)} ({marked})")
            lines.append(description)
            paths = sorted(self._category_paths.get(category, []), reverse=True)
            lines.append(f"{len(paths)} item(s):")
            for size_bytes, path in paths:
                lines.append(f"- {human(size_bytes)}  {path}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def _on_clean_clicked(self, _btn: Gtk.Button) -> None:
        categories = self._selected_categories()
        if not categories:
            self._toast_overlay.add_toast(Adw.Toast(title="Nothing selected", timeout=2))
            return
        total = sum(self._category_bytes.get(c, 0) for c in categories)
        names = ", ".join(CATEGORY_INFO[c][0] for c in categories)
        root = self.get_root()
        confirm(
            root,
            "Clear selected caches?",
            f"This deletes: {names} ({human(total)} total). "
            "Your documents, bookmarks, passwords, and history are untouched.",
            confirm_label="Clear Caches",
            on_confirm=lambda: self._do_clean(categories),
        )

    def _do_clean(self, categories: list[str]) -> None:
        self._set_busy(True)

        def on_done(code: int, lines: list[str]) -> bool:
            self._set_busy(False)
            message = "Cache cleanup complete" if code == 0 else "Cache cleanup failed"
            self._toast_overlay.add_toast(Adw.Toast(title=message, timeout=3))
            self.rescan()
            return False

        run_sync_async(
            "linux_cache_cleanup.sh",
            ["--clean", "--apply", "--only", ",".join(categories)],
            on_done,
            timeout=300.0,
        )

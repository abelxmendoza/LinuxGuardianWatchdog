"""Processes page — the "process killer": list running processes and end
stubborn ones, mirroring the macOS original's Process Killer feature."""
from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

from linuxguardian_ui.dialogs import confirm  # noqa: E402
from linuxguardian_ui.scripts import run_sync_async  # noqa: E402

# ps -eo pid,ppid,%cpu,%mem,etimes,user,comm --no-headers columns, in order.
_COLUMNS = ("pid", "ppid", "cpu", "mem", "etimes", "user", "comm")


class ProcessesPage(Gtk.Box):
    def __init__(self, toast_overlay: Adw.ToastOverlay) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self._toast_overlay = toast_overlay
        self.set_margin_top(16)
        self.set_margin_bottom(16)
        self.set_margin_start(16)
        self.set_margin_end(16)

        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.append(toolbar)

        self.search_entry = Gtk.SearchEntry(hexpand=True, placeholder_text="Filter by name...")
        self.search_entry.connect("search-changed", lambda _e: self._apply_filter())
        toolbar.append(self.search_entry)

        self.sort_dropdown = Gtk.DropDown.new_from_strings(["CPU %", "Memory %"])
        self.sort_dropdown.connect("notify::selected", lambda *_a: self.refresh())
        toolbar.append(self.sort_dropdown)

        refresh_btn = Gtk.Button(label="Refresh")
        refresh_btn.add_css_class("suggested-action")
        refresh_btn.connect("clicked", lambda _b: self.refresh())
        toolbar.append(refresh_btn)

        self.spinner = Gtk.Spinner()
        toolbar.append(self.spinner)

        scroller = Gtk.ScrolledWindow(vexpand=True)
        self.append(scroller)

        self.listbox = Gtk.ListBox()
        self.listbox.add_css_class("omega-card")
        self.listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        scroller.set_child(self.listbox)

        self._all_rows: list[dict[str, str]] = []
        self.refresh()

    # -- data -----------------------------------------------------------
    def refresh(self) -> None:
        self.spinner.start()
        sort_key = "mem" if self.sort_dropdown.get_selected() == 1 else "cpu"
        run_sync_async(
            "linux_process_manager.sh",
            ["--list", "--sort", sort_key],
            self._on_list_done,
        )

    def _on_list_done(self, code: int, lines: list[str]) -> bool:
        self.spinner.stop()
        self._all_rows = []
        for line in lines:
            parts = line.split(None, len(_COLUMNS) - 1)
            if len(parts) != len(_COLUMNS):
                continue
            self._all_rows.append(dict(zip(_COLUMNS, parts)))
        self._apply_filter()
        return False

    def _apply_filter(self) -> None:
        query = self.search_entry.get_text().strip().lower()
        while (child := self.listbox.get_first_child()) is not None:
            self.listbox.remove(child)
        for row in self._all_rows:
            if query and query not in row["comm"].lower():
                continue
            self.listbox.append(self._build_row(row))

    # -- rows -------------------------------------------------------------
    def _build_row(self, proc: dict[str, str]) -> Gtk.Widget:
        row = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL,
            spacing=12,
            margin_top=6,
            margin_bottom=6,
            margin_start=10,
            margin_end=10,
        )

        name_label = Gtk.Label(label=proc["comm"], xalign=0, hexpand=True)
        row.append(name_label)

        pid_label = Gtk.Label(label=f"PID {proc['pid']}")
        pid_label.add_css_class("omega-dim")
        row.append(pid_label)

        cpu_label = Gtk.Label(label=f"{proc['cpu']}% CPU")
        if float(proc["cpu"] or 0) > 50:
            cpu_label.add_css_class("omega-warning")
        row.append(cpu_label)

        mem_label = Gtk.Label(label=f"{proc['mem']}% MEM")
        row.append(mem_label)

        end_btn = Gtk.Button(label="End")
        end_btn.connect("clicked", lambda _b, p=proc: self._confirm_kill(p, force=False))
        row.append(end_btn)

        force_btn = Gtk.Button(label="Force Kill")
        force_btn.add_css_class("destructive-action")
        force_btn.connect("clicked", lambda _b, p=proc: self._confirm_kill(p, force=True))
        row.append(force_btn)

        return row

    # -- actions ----------------------------------------------------------
    def _confirm_kill(self, proc: dict[str, str], force: bool) -> None:
        root = self.get_root()
        verb = "Force kill" if force else "End"
        confirm(
            root,
            f"{verb} {proc['comm']}?",
            f"PID {proc['pid']}, owned by {proc['user']}. "
            + ("This sends SIGKILL immediately." if force else "This asks the process to exit (SIGTERM)."),
            confirm_label=verb,
            on_confirm=lambda: self._do_kill(proc, force),
        )

    def _do_kill(self, proc: dict[str, str], force: bool) -> None:
        args = ["--kill", proc["pid"]]
        if force:
            args.append("--force")

        def on_done(code: int, lines: list[str]) -> bool:
            ok = code == 0
            message = f"Killed {proc['comm']} (PID {proc['pid']})" if ok else f"Failed to kill {proc['comm']}"
            self._toast_overlay.add_toast(Adw.Toast(title=message, timeout=3))
            self.refresh()
            return False

        run_sync_async("linux_process_manager.sh", args, on_done)

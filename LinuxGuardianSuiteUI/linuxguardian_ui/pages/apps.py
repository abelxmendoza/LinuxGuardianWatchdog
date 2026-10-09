"""Apps page: move your apps to another laptop running the same Ubuntu.

Export writes a plain list of app names (no files, passwords or keys). Import first shows exactly what
would happen on THIS laptop (what installs, what is already here, what needs a repository you must add
yourself, what is skipped on purpose); nothing is installed until you confirm, and the only thing
that ever runs as root is a package install behind your desktop's password prompt.
"""
from __future__ import annotations

import json
import socket
import time
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk, Pango  # noqa: E402

from linuxguardian_ui.components import page_header, section_header  # noqa: E402
from linuxguardian_ui.dialogs import confirm  # noqa: E402
from linuxguardian_ui.scripts import run_streaming_async, run_sync_async  # noqa: E402


def _label(text: str, css: str | None = None) -> Gtk.Label:
    label = Gtk.Label(label=text, xalign=0, wrap=True)
    label.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
    if css:
        label.add_css_class(css)
    return label


class AppsPage(Gtk.Box):
    def __init__(self, toast_overlay: Adw.ToastOverlay) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self._toast_overlay = toast_overlay
        self._plan: dict | None = None
        self._manifest_path: str | None = None
        self._busy = False
        for side in ("top", "bottom", "start", "end"):
            getattr(self, f"set_margin_{side}")(24)

        self.append(page_header("Apps", "Move your apps to another laptop running the same Ubuntu.", "folder-download-symbolic"))

        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.append(scroller)
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        scroller.set_child(body)

        # ---- export
        body.append(section_header("1. Save this laptop's apps"))
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        card.add_css_class("omega-card")
        body.append(card)
        card.append(_label("Writes a list of what you installed on purpose (Ubuntu apps, snaps) so another laptop can install the same. "
                           "It contains no files from your home folder, no passwords and no keys. Kernels, NVIDIA/CUDA and other "
                           "hardware-specific packages are marked so they are never copied to different hardware.", "omega-dim"))
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        card.append(row)
        self.export_btn = Gtk.Button(label="Save app list…")
        self.export_btn.add_css_class("suggested-action")
        self.export_btn.connect("clicked", self._on_export)
        row.append(self.export_btn)
        self.spinner = Gtk.Spinner()
        row.append(self.spinner)

        # ---- import
        body.append(section_header("2. Install apps from a list"))
        card2 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        card2.add_css_class("omega-card")
        body.append(card2)
        card2.append(_label("Open a list saved on another laptop. You'll see exactly what would happen on this one before anything is installed. "
                            "It never adds a repository or key, never removes anything, and refuses if the Ubuntu release or CPU differs.", "omega-dim"))
        self.open_btn = Gtk.Button(label="Open app list…", halign=Gtk.Align.START)
        self.open_btn.connect("clicked", self._on_open)
        card2.append(self.open_btn)

        self.plan_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        body.append(self.plan_box)

        self.output = Gtk.TextView(editable=False, monospace=True)
        self.output.add_css_class("omega-card")
        self.output.set_wrap_mode(Gtk.WrapMode.CHAR)
        self.output.set_visible(False)
        self.output.set_size_request(-1, 160)
        body.append(self.output)

    # ---- helpers --------------------------------------------------------
    def _toast(self, text: str) -> None:
        self._toast_overlay.add_toast(Adw.Toast.new(text))

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.export_btn.set_sensitive(not busy)
        self.open_btn.set_sensitive(not busy)
        if busy:
            self.spinner.start()
        else:
            self.spinner.stop()

    def _append(self, line: str) -> bool:
        if line.startswith("LG_PROGRESS"):
            return False
        buf = self.output.get_buffer()
        buf.insert(buf.get_end_iter(), line + "\n")
        self.output.scroll_to_iter(buf.get_end_iter(), 0.0, False, 0.0, 0.0)
        return False

    def _choose_file(self, title: str, save: bool, name: str, on_path) -> None:
        action = Gtk.FileChooserAction.SAVE if save else Gtk.FileChooserAction.OPEN
        dialog = Gtk.FileChooserNative.new(title, self.get_root(), action, "Save" if save else "Open", "Cancel")
        if save:
            dialog.set_current_name(name)
        docs = Path.home() / "Documents"
        if docs.is_dir():
            dialog.set_current_folder(Gio_file(docs))

        def _response(d: Gtk.FileChooserNative, response: int) -> None:
            if response == Gtk.ResponseType.ACCEPT and d.get_file() is not None:
                on_path(d.get_file().get_path())
            d.destroy()

        dialog.connect("response", _response)
        self._chooser = dialog           # keep a reference while it is open
        dialog.show()

    # ---- export ---------------------------------------------------------
    def _on_export(self, _btn: Gtk.Button) -> None:
        name = f"linuxguardian-apps-{socket.gethostname()}-{time.strftime('%Y%m%d')}.json"
        self._choose_file("Save app list", True, name, self._do_export)

    def _do_export(self, path: str) -> None:
        self._set_busy(True)

        def done(code: int, lines: list[str]) -> None:
            self._set_busy(False)
            self._toast(f"Saved app list to {path}" if code == 0 else "Could not save the app list")

        run_sync_async("linux_apps.sh", ["--export", path], done, timeout=180.0)

    # ---- import ---------------------------------------------------------
    def _on_open(self, _btn: Gtk.Button) -> None:
        self._choose_file("Open app list", False, "", self._load_plan)

    def _load_plan(self, path: str) -> None:
        self._manifest_path = path
        self._set_busy(True)

        def done(code: int, lines: list[str]) -> None:
            self._set_busy(False)
            try:
                plan = json.loads("".join(lines))
            except json.JSONDecodeError:
                self._show_error(" ".join(lines)[:300] or "That file isn't a LinuxGuardian app list.")
                return
            self._plan = plan
            self._show_plan(plan)

        run_sync_async("app_manifest.py", ["--plan", path, "--json"], done, timeout=180.0)

    def _clear_plan(self) -> None:
        child = self.plan_box.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.plan_box.remove(child)
            child = nxt

    def _show_error(self, message: str) -> None:
        self._clear_plan()
        self.plan_box.append(_label(message, "omega-critical"))

    def _group(self, title: str, names: list[str], css: str = "omega-dim") -> None:
        if not names:
            return
        expander = Gtk.Expander(label=f"{title} ({len(names)})")
        expander.set_child(_label(", ".join(names), css))
        self.plan_box.append(expander)

    def _show_plan(self, plan: dict) -> None:
        self._clear_plan()
        self.plan_box.append(section_header("What would happen on this laptop"))
        if not plan.get("compatible"):
            self.plan_box.append(_label(plan.get("reason", "This list can't be used here."), "omega-critical"))
            return
        a, s = plan["apt"], plan["snaps"]
        self.plan_box.append(_label(f"From {plan.get('source') or 'another laptop'}.", "omega-dim"))
        self._group("Ubuntu apps that will be installed", a["install"], "omega-heading")
        self._group("Snaps that will be installed", s["install"], "omega-heading")
        self._group("Classic snaps (run unconfined; only if you tick the box below)", s["install_classic"], "omega-warning")
        self._group("Already installed here", sorted(set(a["have"]) | set(s["have"])))
        self._group("Need a third-party repository you would add yourself",
                    [f"{r['name']} (from {r['host']})" for r in a["needs_repo"]], "omega-warning")
        self._group("Hardware-specific, skipped on purpose", a["hardware"])
        self._group("Not available on this laptop", [f"{r['name']}: {r['why']}" for r in a["unavailable"]])
        if plan.get("flatpaks"):
            self._group("Flatpaks (not installed by this app)", [f["id"] for f in plan["flatpaks"]])

        n_apt, n_snap, n_classic = len(a["install"]), len(s["install"]), len(s["install_classic"])
        if n_apt + n_snap + n_classic == 0:
            self.plan_box.append(_label("Nothing to install: everything installable is already here.", "omega-heading"))
            return
        self.classic_check = Gtk.CheckButton(label=f"Also install {n_classic} classic snap(s) (they run unconfined)")
        self.classic_check.set_visible(n_classic > 0)
        self.plan_box.append(self.classic_check)
        install = Gtk.Button(label=f"Install {n_apt} Ubuntu apps and {n_snap} snaps…", halign=Gtk.Align.START)
        install.add_css_class("suggested-action")
        install.connect("clicked", self._confirm_install)
        self.plan_box.append(install)

    def _confirm_install(self, _btn: Gtk.Button) -> None:
        if self._busy or not self._manifest_path:
            return
        include_classic = self.classic_check.get_active()
        confirm(
            self.get_root(),
            "Install these apps?",
            "Your desktop will ask for your password. Only packages shown in the list above are installed, "
            "nothing is removed, and no repositories or keys are added.\n\nThis can take several minutes and "
            "can't be stopped once it starts.",
            "Install",
            lambda: self._install(include_classic),
            destructive=False,
        )

    def _install(self, include_classic: bool) -> None:
        args = ["--install", self._manifest_path or ""]
        if include_classic:
            args.append("--include-classic")
        self.output.get_buffer().set_text("")
        self.output.set_visible(True)
        self._set_busy(True)

        def done(code: int) -> bool:
            self._set_busy(False)
            self._toast({0: "Apps installed", 2: "Cancelled: nothing was changed", 3: "Blocked: nothing was installed"}
                        .get(code, "Install finished with errors, see the output"))
            return False

        run_streaming_async("linux_apps.sh", args, self._append, done)


def Gio_file(path: Path):
    from gi.repository import Gio

    return Gio.File.new_for_path(str(path))

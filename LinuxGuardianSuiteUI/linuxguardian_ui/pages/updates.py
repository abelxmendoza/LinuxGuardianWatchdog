"""Updates page — see what's out of date and install it from here.

Staying patched is one of the most effective defenses there is: most real
compromises use flaws that already have a fix available. This page shows
everything pending (Ubuntu security fixes, other system updates, vendor-repo
apps, snaps) and installs it with one click.

Installing needs root. That goes through the desktop's own password prompt
(polkit); LinuxGuardian never sees the password. See linux_updates.sh.
"""
from __future__ import annotations

import json
import re

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk, Pango  # noqa: E402

from linuxguardian_ui.clipboard import copy_text  # noqa: E402
from linuxguardian_ui.dialogs import confirm  # noqa: E402
from linuxguardian_ui.progress import is_progress_noise, parse_progress_line  # noqa: E402
from linuxguardian_ui.scripts import run_streaming_async, run_sync_async  # noqa: E402

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# dpkg redraws "(Reading database ... 45%" dozens of times; keep the log readable.
_DPKG_NOISE_RE = re.compile(r"^\(?Reading database \.\.\. \d+%")

# (category id, heading, plain-language blurb, expanded by default)
SECTIONS = (
    (
        "security",
        "Security updates",
        "Fixes for known vulnerabilities. These are the ones that actually protect you, so install them first.",
        True,
    ),
    (
        "standard",
        "Other system updates",
        "Bug fixes and improvements from Ubuntu. Low risk.",
        False,
    ),
    (
        "third_party",
        "Third-party apps",
        "From vendor repositories you added (for example Claude, Cursor, ChatGPT, Tailscale). "
        "Ubuntu's automatic updater does not cover these, so this is the only way they stay current. "
        "Only update from sources you trust.",
        False,
    ),
    (
        "snap",
        "Snap apps",
        "Sandboxed apps from the Snap Store (Firefox, VS Code, ...). Snaps normally refresh themselves "
        "in the background; this just does it now.",
        False,
    ),
)
CATEGORY_TITLES = {cid: title for cid, title, _blurb, _open in SECTIONS}


def _label(text: str, css: str | None = None, *, selectable: bool = False) -> Gtk.Label:
    label = Gtk.Label(label=text, xalign=0, wrap=True, selectable=selectable)
    if css:
        label.add_css_class(css)
    return label


def _fmt_age(seconds: int | None) -> str:
    if seconds is None:
        return "unknown"
    if seconds < 90:
        return "just now"
    if seconds < 5400:
        return f"{seconds // 60}m ago"
    if seconds < 172800:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


class UpdatesPage(Gtk.Box):
    def __init__(self, toast_overlay: Adw.ToastOverlay) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self._toast_overlay = toast_overlay
        self.set_margin_top(16)
        self.set_margin_bottom(16)
        self.set_margin_start(16)
        self.set_margin_end(16)

        self._meta: dict = {}
        self._pkgs: list[dict] = []
        self._busy = False
        self._checking = False
        self._pulse_id = 0
        self._job: dict = {}
        self._stack_buttons: list[Gtk.Button] = []

        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.append(toolbar)

        self.check_btn = Gtk.Button(label="Check for Updates")
        self.check_btn.connect("clicked", lambda _b: self.check())
        toolbar.append(self.check_btn)

        self.all_btn = Gtk.Button(label="Update Everything")
        self.all_btn.add_css_class("suggested-action")
        self.all_btn.set_tooltip_text(
            "Installs security, system, third-party and snap updates. Never removes packages."
        )
        self.all_btn.connect("clicked", lambda _b: self._confirm_apply(security_only=False))
        toolbar.append(self.all_btn)

        self.sec_btn = Gtk.Button(label="Security Only")
        self.sec_btn.set_tooltip_text(
            "Installs just the security fixes (the same ones Ubuntu's automatic updater applies)."
        )
        self.sec_btn.connect("clicked", lambda _b: self._confirm_apply(security_only=True))
        toolbar.append(self.sec_btn)

        copy_btn = Gtk.Button(label="Copy All")
        copy_btn.connect("clicked", self._on_copy_all)
        toolbar.append(copy_btn)

        self.spinner = Gtk.Spinner()
        toolbar.append(self.spinner)

        intro = _label(
            "Staying patched is one of the best defenses you have: most break-ins use flaws that already "
            "have a fix. Installing asks for your password through the system prompt; LinuxGuardian never "
            "sees it, and it never removes packages.",
            "omega-dim",
        )
        self.append(intro)

        scroller = Gtk.ScrolledWindow(vexpand=True)
        self.append(scroller)

        self.content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        scroller.set_child(self.content)

        # The install card goes FIRST so it is visible the moment an install
        # starts. Below a long package list it was off-screen, and the only
        # visible sign of activity was greyed-out buttons.
        self._build_run_card()

        self.status_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.content.append(self.status_box)

        self.sections_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.content.append(self.sections_box)

        self.stacks_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.content.append(self.stacks_box)

        self.check()

    # -- install progress card ------------------------------------------------
    def _build_run_card(self) -> None:
        self.run_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.run_card.add_css_class("omega-card")
        self.run_card.set_visible(False)
        self.content.append(self.run_card)

        heading_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.run_card.append(heading_row)

        self.run_spinner = Gtk.Spinner()
        heading_row.append(self.run_spinner)

        self.run_title = Gtk.Label(label="Installing updates", xalign=0, hexpand=True)
        self.run_title.add_css_class("omega-heading")
        self.run_title.add_css_class("title-3")
        heading_row.append(self.run_title)

        self.run_subtitle = _label("")
        self.run_card.append(self.run_subtitle)

        self.run_bar = Gtk.ProgressBar(show_text=True, hexpand=True)
        self.run_bar.set_pulse_step(0.08)
        self.run_card.append(self.run_bar)

        note = _label(
            "This can't be safely interrupted once it starts. Closing this window won't stop it; "
            "the work finishes in the background and is logged to ~/.linuxguardian/logs/updates/.",
            "omega-dim",
        )
        self.run_card.append(note)

        scroller = Gtk.ScrolledWindow(min_content_height=200)
        self.run_card.append(scroller)
        self.output_view = Gtk.TextView(editable=False, monospace=True)
        self.output_view.set_wrap_mode(Gtk.WrapMode.CHAR)
        scroller.set_child(self.output_view)
        self.buffer = self.output_view.get_buffer()
        self._end_mark = self.buffer.create_mark("tail", self.buffer.get_end_iter(), False)

    # -- checking -------------------------------------------------------------
    def check(self) -> None:
        if self._busy or self._checking:
            return
        self._checking = True
        self.spinner.start()
        self._update_buttons()
        run_sync_async("linux_updates.sh", ["--check", "--json"], self._on_check_done, timeout=120.0)

    def _on_check_done(self, code: int, lines: list[str]) -> bool:
        self._checking = False
        self.spinner.stop()
        meta: dict = {}
        pkgs: list[dict] = []
        for line in lines:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("type") == "meta":
                meta = row
            elif row.get("type") == "pkg":
                pkgs.append(row)
        self._meta, self._pkgs = meta, pkgs
        self._render()
        if not meta:
            self._toast_overlay.add_toast(Adw.Toast(title="Couldn't check for updates", timeout=3))
        return False

    # -- rendering ------------------------------------------------------------
    def _counts(self) -> dict[str, int]:
        result = {cid: 0 for cid, *_rest in SECTIONS}
        for pkg in self._pkgs:
            result[pkg["category"]] = result.get(pkg["category"], 0) + 1
        return result

    def _render(self) -> None:
        self._render_status()
        self._render_sections()
        self._render_stacks()
        self._update_buttons()

    def _clear(self, box: Gtk.Box) -> None:
        while (child := box.get_first_child()) is not None:
            box.remove(child)

    def _render_status(self) -> None:
        self._clear(self.status_box)
        meta = self._meta
        if not meta:
            self.status_box.append(
                _label("Couldn't read update status. Try Check for Updates again.", "omega-warning")
            )
            return

        if meta.get("auto_security_updates") == "on":
            self.status_box.append(
                _label(
                    "Automatic security updates: ON. Ubuntu's security patches install on their own every day.",
                    "omega-heading",
                )
            )
        else:
            self.status_box.append(
                _label(
                    "Automatic security updates: OFF. Your system isn't installing security patches by itself. "
                    "Turn them on with:  sudo dpkg-reconfigure -plow unattended-upgrades",
                    "omega-critical",
                    selectable=True,
                )
            )

        guard = meta.get("release_guard") or {}
        if guard.get("applicable") and not guard.get("ok", True):
            self.status_box.append(
                _label(
                    "Release guard: installing is DISABLED. Something on this system points at a "
                    f"different Ubuntu release than the one you're running ('{guard.get('codename', '?')}'). "
                    "Installing now could leave a half-finished release upgrade, so nothing will be "
                    "installed until it's fixed:",
                    "omega-critical",
                )
            )
            for problem in guard.get("problems", []):
                self.status_box.append(_label("  •  " + problem, "omega-warning", selectable=True))
        elif guard.get("applicable"):
            self.status_box.append(
                _label(
                    f"Release guard: OK. Every update source is for '{guard.get('codename', '?')}', "
                    "so updates can't move you to another Ubuntu release.",
                    "omega-dim",
                )
            )

        age = meta.get("cache_age_sec")
        age_text = f"Package lists last refreshed: {_fmt_age(age)}"
        if age is not None and age > 3 * 86400:
            self.status_box.append(
                _label(age_text + " (stale; installing refreshes them first)", "omega-warning")
            )
        else:
            self.status_box.append(_label(age_text, "omega-dim"))

        if meta.get("reboot_required"):
            pkgs = ", ".join(meta.get("reboot_pkgs") or [])
            self.status_box.append(
                _label(
                    "Restart required to finish applying earlier updates"
                    + (f" ({pkgs})." if pkgs else "."),
                    "omega-warning",
                )
            )
        if not meta.get("snap_checked"):
            self.status_box.append(
                _label(
                    "Couldn't reach the Snap Store, so snap updates aren't shown (offline?).",
                    "omega-dim",
                )
            )

    def _render_sections(self) -> None:
        self._clear(self.sections_box)

        heading = Gtk.Label(label="Available updates", xalign=0)
        heading.add_css_class("omega-heading")
        heading.add_css_class("title-4")
        self.sections_box.append(heading)

        if not self._meta:
            return

        shown = 0
        for category, title, blurb, expanded in SECTIONS:
            items = [p for p in self._pkgs if p["category"] == category]
            if not items:
                continue
            shown += 1
            self.sections_box.append(self._build_section(title, blurb, items, expanded))

        kept = self._meta.get("apt_kept_back") or []
        if kept:
            shown += 1
            self.sections_box.append(self._build_held_back(kept))

        if not self._pkgs:
            self.sections_box.append(
                _label("Everything is up to date.", "omega-heading")
            )

    def _build_section(self, title: str, blurb: str, items: list[dict], expanded: bool) -> Gtk.Widget:
        n = len(items)
        expander = Gtk.Expander(label=f"{title}  —  {n} package{'s' if n != 1 else ''}")
        expander.set_expanded(expanded)

        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_top=8, margin_start=8)
        expander.set_child(inner)
        inner.append(_label(blurb, "omega-dim"))

        listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        listbox.add_css_class("omega-card")
        for pkg in sorted(items, key=lambda p: p["name"]):
            listbox.append(self._build_row(pkg))
        inner.append(listbox)
        return expander

    def _build_row(self, pkg: dict) -> Gtk.Widget:
        row = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL,
            spacing=12,
            margin_top=6,
            margin_bottom=6,
            margin_start=10,
            margin_end=10,
        )
        name = Gtk.Label(label=pkg["name"], xalign=0, hexpand=True)
        row.append(name)

        if pkg["manager"] == "snap":
            detail = f"{pkg['candidate']}  ·  {pkg.get('size', '')}  ·  {pkg.get('origin', '')}"
            if pkg.get("notes") and pkg["notes"] != "-":
                detail += f"  ·  {pkg['notes']}"
        elif pkg.get("installed"):
            detail = f"{pkg['installed']}  →  {pkg['candidate']}"
        else:
            detail = pkg["candidate"]
        version = Gtk.Label(label=detail, xalign=1, ellipsize=Pango.EllipsizeMode.END, max_width_chars=60)
        version.add_css_class("omega-dim")
        row.append(version)
        return row

    def _build_held_back(self, names: list[str]) -> Gtk.Widget:
        n = len(names)
        expander = Gtk.Expander(label=f"Held back  —  {n} package{'s' if n != 1 else ''}")
        expander.set_expanded(False)
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_top=8, margin_start=8)
        expander.set_child(inner)
        inner.append(
            _label(
                "These need a full upgrade, which can add or remove other packages (GPU driver version "
                "changes are a common case). LinuxGuardian won't do that for you, because getting it wrong "
                "can leave a machine without a working display. Review them yourself, then run "
                "'sudo apt full-upgrade' when you're ready.",
                "omega-warning",
            )
        )
        inner.append(_label("  ".join(names), "omega-dim", selectable=True))
        return expander

    def _update_buttons(self) -> None:
        counts = self._counts()
        total = sum(counts.values())
        idle = not (self._busy or self._checking)
        self.check_btn.set_sensitive(idle)
        self.all_btn.set_label(f"Update Everything ({total})" if total else "Update Everything")
        self.sec_btn.set_label(
            f"Security Only ({counts['security']})" if counts["security"] else "Security Only"
        )
        blocked = self._guard_blocked()
        self.all_btn.set_sensitive(idle and total > 0 and not blocked)
        self.sec_btn.set_sensitive(idle and counts["security"] > 0 and not blocked)
        if blocked:
            why = "Disabled by the release guard: see the red notice above."
            self.all_btn.set_tooltip_text(why)
            self.sec_btn.set_tooltip_text(why)
        for btn in self._stack_buttons:
            btn.set_sensitive(idle)

    def _guard_blocked(self) -> bool:
        guard = self._meta.get("release_guard") or {}
        return bool(guard.get("applicable")) and not guard.get("ok", True)

    # -- pinned stacks ----------------------------------------------------------
    def _render_stacks(self) -> None:
        self._clear(self.stacks_box)
        self._stack_buttons = []
        meta = self._meta
        groups = [g for g in (meta.get("hold_groups") or []) if g["state"] != "absent"]
        held_other = meta.get("held_other") or []
        if not meta or not (groups or held_other):
            return

        heading = Gtk.Label(label="Pinned stacks", xalign=0)
        heading.add_css_class("omega-heading")
        heading.add_css_class("title-4")
        self.stacks_box.append(heading)
        self.stacks_box.append(
            _label(
                "Freeze a stack once it works (ROS, Gazebo, the GPU driver) so nothing updates it: not "
                "this app, not Ubuntu's Software Updater, not the automatic updater. Held packages also "
                "skip their own security fixes, so release a stack when you're ready to update it.",
                "omega-dim",
            )
        )

        listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        listbox.add_css_class("omega-card")
        for group in groups:
            listbox.append(self._build_stack_row(group))
        if groups:
            self.stacks_box.append(listbox)

        waiting = meta.get("held_with_updates") or []
        if waiting:
            names = ", ".join(w["name"] for w in waiting[:6]) + (" ..." if len(waiting) > 6 else "")
            self.stacks_box.append(
                _label(
                    f"{len(waiting)} held package(s) have newer versions waiting ({names}). That's "
                    "expected while a stack is frozen; release the stack to update it.",
                    "omega-warning",
                )
            )
        if held_other:
            self.stacks_box.append(
                _label(
                    "Also held outside LinuxGuardian: " + ", ".join(held_other[:8])
                    + (" ..." if len(held_other) > 8 else "")
                    + ".  Release one with: sudo apt-mark unhold <name>",
                    "omega-dim",
                    selectable=True,
                )
            )

    def _build_stack_row(self, group: dict) -> Gtk.Widget:
        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=2,
            margin_top=8, margin_bottom=8, margin_start=10, margin_end=10,
        )
        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        outer.append(top)
        top.append(Gtk.Label(label=group["label"], xalign=0, hexpand=True))

        state = group["state"]
        if state == "all":
            text, css = f"Held ({group['held']} packages)", "omega-heading"
        elif state == "partial":
            text, css = f"Partly held ({group['held']} of {group['installed']})", "omega-warning"
        else:
            text, css = f"Not held ({group['installed']} packages)", "omega-dim"
        status = Gtk.Label(label=text)
        status.add_css_class(css)
        top.append(status)

        if state in ("none", "partial"):
            hold = Gtk.Button(label="Hold the rest" if state == "partial" else "Hold")
            hold.connect("clicked", lambda _b, g=group: self._confirm_hold(g, release=False))
            top.append(hold)
            self._stack_buttons.append(hold)
        if state in ("all", "partial"):
            release = Gtk.Button(label="Release")
            release.connect("clicked", lambda _b, g=group: self._confirm_hold(g, release=True))
            top.append(release)
            self._stack_buttons.append(release)

        outer.append(_label(group["blurb"], "omega-dim"))
        return outer

    def _confirm_hold(self, group: dict, release: bool) -> None:
        if release:
            n = group["held"]
            heading = f"Release {group['label']}?"
            body = (
                f"Un-freezes {n} packages. They'll update again with everything else, including "
                "Ubuntu's automatic updates."
            )
        else:
            n = group["installed"] - group["held"]
            heading = f"Hold {group['label']}?"
            body = (
                f"Freezes {n} packages (apt-mark hold). LinuxGuardian, Ubuntu's Software Updater and the "
                "automatic updater will all skip them until you release the stack. Held packages also "
                "miss their own security fixes, so remember to release it when you want to update."
            )
        confirm(
            self.get_root(),
            heading,
            body + " You'll get a system password prompt (LinuxGuardian never sees it).",
            confirm_label="Release" if release else "Hold",
            on_confirm=lambda: self._start_hold(group, release),
            destructive=False,
        )

    def _start_hold(self, group: dict, release: bool) -> None:
        verb = "unhold" if release else "hold"
        label = group["label"]
        self._start_job(
            [f"--{verb}", group["id"]],
            running_title=f"{'Releasing' if release else 'Holding'} {label}",
            ok_title=f"{label} released" if release else f"{label} held",
            ok_toast=f"{label} released" if release else f"{label} held",
            waiting="Waiting for your password…",
        )

    # -- copy -----------------------------------------------------------------
    def _on_copy_all(self, _btn: Gtk.Button) -> None:
        if not self._meta:
            self._toast_overlay.add_toast(Adw.Toast(title="Nothing to copy yet", timeout=2))
            return
        try:
            copy_text(self._list_as_text())
        except Exception as exc:  # noqa: BLE001
            self._toast_overlay.add_toast(Adw.Toast(title=f"Copy failed: {exc}", timeout=3))
            return
        self._toast_overlay.add_toast(Adw.Toast(title="Update list copied", timeout=2))

    def _list_as_text(self) -> str:
        meta = self._meta
        lines = [
            "LinuxGuardian Watchdog — pending software updates",
            "Please explain which of these matter most for security, anything risky to update, "
            "and the safest order to install them.",
            f"Automatic security updates: {str(meta.get('auto_security_updates', '?')).upper()}",
            f"Package lists refreshed: {_fmt_age(meta.get('cache_age_sec'))}",
            f"Restart required: {'yes' if meta.get('reboot_required') else 'no'}",
        ]
        guard = meta.get("release_guard") or {}
        if guard.get("applicable"):
            lines.append(
                f"Release guard: {'OK' if guard.get('ok') else 'BLOCKED'} (system is '{guard.get('codename')}')"
            )
            lines.extend(f"  - {p}" for p in guard.get("problems", []))
        stacks = [g for g in (meta.get("hold_groups") or []) if g["state"] != "absent"]
        if stacks:
            lines.append(
                "Pinned stacks: "
                + "; ".join(f"{g['label']}: {g['state']} ({g['held']}/{g['installed']} held)" for g in stacks)
            )
        lines.append("")
        for category, title, _blurb, _open in SECTIONS:
            items = [p for p in self._pkgs if p["category"] == category]
            if not items:
                continue
            lines.append(f"## {title} ({len(items)})")
            for pkg in sorted(items, key=lambda p: p["name"]):
                if pkg.get("installed"):
                    lines.append(f"- {pkg['name']}  {pkg['installed']} -> {pkg['candidate']}")
                else:
                    lines.append(f"- {pkg['name']}  {pkg['candidate']}")
            lines.append("")
        kept = meta.get("apt_kept_back") or []
        if kept:
            lines.append(f"## Held back ({len(kept)}) — needs a full upgrade, not done automatically")
            lines.append(", ".join(kept))
        return "\n".join(lines).rstrip() + "\n"

    # -- installing -------------------------------------------------------------
    def _confirm_apply(self, security_only: bool) -> None:
        counts = self._counts()
        if security_only:
            heading = f"Install {counts['security']} security updates?"
            what = (
                "Installs just the pending security fixes, the same ones Ubuntu's automatic updater "
                "applies. Other updates, third-party apps and snaps are left alone."
            )
        else:
            total = sum(counts.values())
            heading = f"Install {total} updates?"
            what = (
                f"Installs {counts['security']} security, {counts['standard']} other system, "
                f"{counts['third_party']} third-party and {counts['snap']} snap updates. "
                "Packages that need removals are held back, never forced."
            )
        confirm(
            self.get_root(),
            heading,
            what + " You'll get a system password prompt (LinuxGuardian never sees it). "
            "Once started this can't be safely interrupted. Some apps may need a restart afterwards.",
            confirm_label="Install",
            on_confirm=lambda: self._start_apply(security_only),
            destructive=False,
        )

    def _start_apply(self, security_only: bool) -> None:
        self._start_job(
            ["--apply"] + (["--security-only"] if security_only else []),
            running_title="Installing security updates" if security_only else "Installing updates",
            ok_title="Updates installed",
            ok_toast="Updates installed",
            waiting="Waiting for your password…",
        )

    def _start_job(self, args: list[str], running_title: str, ok_title: str, ok_toast: str, waiting: str) -> None:
        """Run a linux_updates.sh action (install or hold) behind the progress card."""
        self._job = {"ok_title": ok_title, "ok_toast": ok_toast}
        self._busy = True
        self._update_buttons()
        self.run_card.set_visible(True)
        self.buffer.set_text("")
        self.run_title.set_label(running_title)
        self.run_subtitle.set_label(waiting)
        self.run_bar.set_fraction(0)
        self.run_bar.set_text(waiting)
        self.run_spinner.start()
        if self._pulse_id:
            GLib.source_remove(self._pulse_id)
        self._pulse_id = GLib.timeout_add(250, self._pulse)

        # No cancel handle is kept on purpose: the root-side work can't be
        # safely stopped from here, so the UI offers no Stop button.
        run_streaming_async("linux_updates.sh", args, self._on_line, self._on_job_done)

    def _pulse(self) -> bool:
        if not self._busy:
            self._pulse_id = 0
            return False
        self.run_bar.pulse()
        return True

    def _on_line(self, line: str) -> bool:
        line = _ANSI_RE.sub("", line)
        if line.startswith("LG_PROGRESS"):
            progress = parse_progress_line(line)
            if progress and progress.message:
                if progress.step and progress.steps:
                    text = f"Step {progress.step} of {progress.steps}: {progress.message}"
                else:
                    text = progress.message
                self.run_subtitle.set_label(text)
                self.run_bar.set_text(progress.message)
            return False
        if _DPKG_NOISE_RE.match(line) or is_progress_noise(line):
            return False
        self.buffer.insert(self.buffer.get_end_iter(), line + "\n")
        self.buffer.move_mark(self._end_mark, self.buffer.get_end_iter())
        self.output_view.scroll_to_mark(self._end_mark, 0.0, False, 0.0, 0.0)
        return False

    def _on_job_done(self, code: int) -> bool:
        self._busy = False
        self.run_spinner.stop()
        if code == 0:
            self.run_title.set_label(self._job.get("ok_title", "Done"))
            self.run_subtitle.set_label("Done. Re-checking…")
            self.run_bar.set_fraction(1.0)
            self.run_bar.set_text("Done")
            toast = self._job.get("ok_toast", "Done")
        elif code == 2:
            self.run_title.set_label("Cancelled")
            self.run_subtitle.set_label("The password prompt was cancelled or failed. Nothing was changed.")
            self.run_bar.set_fraction(0)
            self.run_bar.set_text("Cancelled")
            toast = "Cancelled, nothing changed"
        elif code == 3:
            self.run_title.set_label("Blocked by the release guard")
            self.run_subtitle.set_label("Nothing was installed. The reason is in the output below.")
            self.run_bar.set_fraction(0)
            self.run_bar.set_text("Blocked")
            toast = "Blocked by the release guard, nothing installed"
        else:
            self.run_title.set_label("Finished with errors")
            self.run_subtitle.set_label("Some steps failed. Details are in the output below and the log.")
            self.run_bar.set_fraction(0)
            self.run_bar.set_text("Errors")
            toast = "Finished with errors"
        self._toast_overlay.add_toast(Adw.Toast(title=toast, timeout=4))
        self._update_buttons()
        GLib.timeout_add(600, lambda: (self.check(), False)[1])
        return False

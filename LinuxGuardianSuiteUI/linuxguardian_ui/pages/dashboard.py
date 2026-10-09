"""Dashboard page: security score, scans, and live output."""
from __future__ import annotations

import json
import os
import re
import signal
import time
from collections.abc import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk, Pango  # noqa: E402

from linuxguardian_ui.components import page_header, section_header
from linuxguardian_ui.dialogs import confirm, review

from linuxguardian_ui.progress import (  # noqa: E402
    Progress,
    format_duration,
    is_progress_noise,
    merge_progress,
    overall_fraction,
    parse_progress_line,
    phase_label,
    remaining_text,
)
from linuxguardian_ui.live_scan import find_running_scan, human_bytes, snapshot  # noqa: E402
from linuxguardian_ui.scan_history import (  # noqa: E402
    ensure_last_scan,
    format_last_scan,
    last_scan_severity,
    load_last_scan,
)
from linuxguardian_ui.score import parse_audit_score  # noqa: E402
from linuxguardian_ui.scripts import run_streaming_async, run_sync_async  # noqa: E402

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class DashboardPage(Gtk.Box):
    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_margin_top(24)
        self.set_margin_bottom(24)
        self.set_margin_start(24)
        self.set_margin_end(24)

        self.append(page_header("Security dashboard", "Scan, inspect, and maintain your Linux desktop.", "security-high-symbolic", logo=True))
        overview = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12, homogeneous=True)
        self.append(overview)

        score_card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        score_card.add_css_class("omega-card")
        score_card.set_margin_top(4)
        score_card.set_margin_bottom(4)
        score_card.set_margin_start(10)
        score_card.set_margin_end(10)
        overview.append(score_card)

        self.score_label = Gtk.Label(label="—")
        self.score_label.add_css_class("omega-heading")
        self.score_label.add_css_class("title-1")
        score_card.append(self.score_label)

        score_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        score_card.append(score_text)

        title = Gtk.Label(label="Security Score", xalign=0)
        title.add_css_class("omega-heading")
        score_text.append(title)

        self.score_detail = Gtk.Label(label="Run the audit to see your score.", xalign=0, wrap=True)
        self.score_detail.add_css_class("omega-dim")
        score_text.append(self.score_detail)

        last_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        last_card.add_css_class("omega-card")
        last_card.set_margin_start(10)
        last_card.set_margin_end(10)
        overview.append(last_card)

        last_heading = Gtk.Label(label="Last malware scan", xalign=0)
        last_heading.add_css_class("omega-dim")
        last_card.append(last_heading)

        self.last_scan_title = Gtk.Label(label="No scan saved yet", xalign=0)
        self.last_scan_title.add_css_class("omega-heading")
        last_card.append(self.last_scan_title)

        self.last_scan_detail = Gtk.Label(
            label="Run a scan to store the result. Later scans can skip unchanged files.",
            xalign=0,
            wrap=True,
        )
        self.last_scan_detail.add_css_class("omega-dim")
        last_card.append(self.last_scan_detail)

        self.append(section_header("Scanner health"))
        self.health_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.health_card.add_css_class("omega-card")
        self.health_card.set_margin_start(10)
        self.health_card.set_margin_end(10)
        self.health_card.append(Gtk.Label(label="Checking scanner health…", xalign=0))
        self.append(self.health_card)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        actions.add_css_class("process-toolbar")
        self.append(section_header("Quick actions"))
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

        self.update_defs_btn = Gtk.Button(label="Update Definitions")
        self.update_defs_btn.set_tooltip_text(
            "Downloads the latest virus definitions (freshclam). Asks for your password through the desktop's own prompt."
        )
        self.update_defs_btn.connect("clicked", self._on_update_defs_clicked)
        actions.append(self.update_defs_btn)

        self.stop_btn = Gtk.Button(label="Stop")
        self.stop_btn.add_css_class("destructive-action")
        self.stop_btn.set_sensitive(False)
        self.stop_btn.connect("clicked", self._on_stop_clicked)
        actions.append(self.stop_btn)

        self.spinner = Gtk.Spinner()
        actions.append(self.spinner)

        scan_opts = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.append(scan_opts)

        self.full_check = Gtk.CheckButton(label="Include developer tools and build caches")
        self.full_check.set_tooltip_text("Adds SDKs, compiler caches, and git objects to the scan — takes longer but is more thorough")
        scan_opts.append(self.full_check)

        self.rootkit_check = Gtk.CheckButton(label="Include rootkit check (asks for your password)")
        self.rootkit_check.set_tooltip_text(
            "rkhunter only works as root. Your desktop shows its own password prompt; this app never sees the password. "
            "Once approved, the rootkit check can't be stopped from here."
        )
        self.rootkit_check.set_active(True)
        scan_opts.append(self.rootkit_check)

        self.changed_check = Gtk.CheckButton(label="Scan only files modified since last scan")
        self.changed_check.set_tooltip_text("Skips files that haven't changed — much faster, but relies on a previous scan existing")
        self.changed_check.set_active(True)
        scan_opts.append(self.changed_check)

        self.progress_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.progress_card.add_css_class("omega-card")
        self.progress_card.set_margin_start(0)
        self.progress_card.set_margin_end(0)
        self.progress_card.set_visible(False)
        self.append(self.progress_card)

        heading_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.progress_card.append(heading_row)

        self.progress_spinner = Gtk.Spinner()
        heading_row.append(self.progress_spinner)

        self.progress_title = Gtk.Label(label="Working…", xalign=0, hexpand=True)
        self.progress_title.add_css_class("omega-heading")
        self.progress_title.add_css_class("title-3")
        heading_row.append(self.progress_title)

        self.progress_subtitle = Gtk.Label(label="", xalign=0, wrap=True)
        self.progress_card.append(self.progress_subtitle)

        self.progress_bar = Gtk.ProgressBar(show_text=True, hexpand=True)
        self.progress_bar.set_pulse_step(0.08)
        self.progress_card.append(self.progress_bar)

        times = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.progress_card.append(times)

        self.elapsed_label = Gtk.Label(label="Elapsed 0s", xalign=0, hexpand=True)
        times.append(self.elapsed_label)

        self.remaining_label = Gtk.Label(label="", xalign=1, hexpand=True)
        self.remaining_label.add_css_class("omega-dim")
        times.append(self.remaining_label)

        self.current_label = Gtk.Label(label="", xalign=0, hexpand=True)
        self.current_label.add_css_class("omega-dim")
        self.current_label.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
        self.progress_card.append(self.current_label)

        self.append(section_header("Activity output"))
        scroller = Gtk.ScrolledWindow(vexpand=True)
        self.append(scroller)

        self.output_view = Gtk.TextView(editable=False, monospace=True)
        self.output_view.add_css_class("omega-card")
        self.output_view.set_wrap_mode(Gtk.WrapMode.CHAR)
        scroller.set_child(self.output_view)
        self.buffer = self.output_view.get_buffer()
        self._end_mark = self.buffer.create_mark("tail", self.buffer.get_end_iter(), False)

        self._current_lines: list[str] = []
        self._busy = False
        self._job_label = ""
        self._started_at = 0.0
        self._tick_id = 0
        self._attach_tick_id = 0
        self._cancel: Callable[[], None] | None = None
        self._last_progress: Progress | None = None
        self._unstoppable = False      # a root-owned step is running: the user can't signal it
        self._rootkit_job = False
        self._attached_scan = find_running_scan()
        self._refresh_last_scan()
        self._refresh_health()
        if not self._attach_running_scan():
            self._on_audit_clicked(None)

    def _set_window_title(self, suffix: str | None) -> None:
        win = self.get_root()
        if win is None:
            return
        title = "LinuxGuardian Watchdog" if not suffix else f"LinuxGuardian Watchdog — {suffix}"
        win.set_title(title)  # type: ignore[attr-defined]

    def _set_busy(self, busy: bool, label: str = "") -> None:
        self._busy = busy
        self._job_label = label
        for btn in (self.scan_btn, self.integrity_btn, self.audit_btn, self.update_defs_btn):
            btn.set_sensitive(not busy)
        self.stop_btn.set_sensitive(busy and not self._unstoppable)
        if busy:
            self._started_at = time.monotonic()
            self._last_progress = None
            self.progress_card.set_visible(True)
            self.progress_title.set_label(f"{label} in progress")
            self.progress_subtitle.set_label("Started — elapsed time will keep ticking even while the scanner is quiet.")
            for _cls in ("omega-heading", "omega-warning"):
                self.remaining_label.remove_css_class(_cls)
            self.remaining_label.add_css_class("omega-dim")
            self.remaining_label.set_label("Still running")
            self.elapsed_label.set_label("Elapsed 0s")
            self.current_label.set_label("")
            self.progress_bar.set_fraction(0)
            self.progress_bar.set_text("Working…")
            self.spinner.start()
            self.progress_spinner.start()
            if self._tick_id:
                GLib.source_remove(self._tick_id)
            self._tick_id = GLib.timeout_add(250, self._on_tick)
            self._set_window_title(f"{label} running")
        else:
            self.spinner.stop()
            self.progress_spinner.stop()
            if self._tick_id:
                GLib.source_remove(self._tick_id)
                self._tick_id = 0
            self._set_window_title(None)

    def _on_tick(self) -> bool:
        if not self._busy:
            return False
        elapsed = time.monotonic() - self._started_at
        self.elapsed_label.set_label(f"Elapsed {format_duration(elapsed)}")
        progress = self._last_progress
        frac = overall_fraction(progress) if progress else None
        if frac is None:
            self.progress_bar.pulse()
            self.progress_bar.set_text("Working…")
        else:
            self.progress_bar.set_fraction(frac)
            self.progress_bar.set_text(f"{int(round(frac * 100))}%")
        self.remaining_label.set_label(remaining_text(elapsed, progress))
        return True

    def _apply_progress(self, progress: Progress) -> None:
        merged = merge_progress(self._last_progress, progress)
        self._last_progress = merged
        parts: list[str] = []
        if merged.step and merged.steps:
            parts.append(f"Step {merged.step} of {merged.steps}")
        if merged.phase:
            parts.append(phase_label(merged.phase))
        if merged.message:
            parts.append(merged.message)
        if self._rootkit_job and merged.phase == "rkhunter" and not self._unstoppable:
            # From here the work is done by a root process that this app can't signal.
            self._unstoppable = True
            self.stop_btn.set_sensitive(False)
        if self._unstoppable:
            parts.append("runs as root, can't be stopped from here")
        self.progress_subtitle.set_label(" · ".join(parts) if parts else "Running")
        if merged.current:
            counts = ""
            if merged.done is not None and merged.total:
                counts = f" ({merged.done} / {merged.total})"
            elif merged.done is not None:
                counts = f" ({merged.done} files)"
            self.current_label.set_label(f"Current: {merged.current}{counts}")
        elif merged.done is not None:
            total = f" / {merged.total}" if merged.total else ""
            self.current_label.set_label(f"Processed {merged.done}{total}")

    def _append_line(self, line: str) -> bool:
        line = _ANSI_RE.sub("", line)
        progress = parse_progress_line(line)
        if progress:
            self._apply_progress(progress)
            return False
        if is_progress_noise(line):
            return False
        self._current_lines.append(line)
        end = self.buffer.get_end_iter()
        self.buffer.insert(end, line + "\n")
        self.buffer.move_mark(self._end_mark, self.buffer.get_end_iter())
        self.output_view.scroll_to_mark(self._end_mark, 0.0, False, 0.0, 0.0)
        return False

    def _clear(self) -> None:
        self._current_lines = []
        self.buffer.set_text("")

    def _set_remaining_color(self, css: str) -> None:
        for cls in ("omega-dim", "omega-warning", "omega-heading"):
            self.remaining_label.remove_css_class(cls)
        self.remaining_label.add_css_class(css)

    def _finish_progress(self, code: int, label: str) -> None:
        elapsed = time.monotonic() - self._started_at if self._started_at else 0.0
        took = format_duration(elapsed)
        if code == 130:
            self.progress_title.set_label(f"{label} stopped")
            self.remaining_label.set_label(f"Stopped after {took}")
            self.progress_bar.set_text("Stopped")
            self._set_remaining_color("omega-dim")
        elif code == 0:
            self.progress_title.set_label(f"{label} finished")
            self.remaining_label.set_label(f"Completed in {took}")
            self.progress_bar.set_fraction(1.0)
            self.progress_bar.set_text("Done")
            self._set_remaining_color("omega-heading")
        else:
            self.progress_title.set_label(f"{label} finished with errors")
            self.remaining_label.set_label(f"Exited after {took}")
            self._set_remaining_color("omega-warning")

    def _attach_running_scan(self) -> bool:
        scan = self._attached_scan or find_running_scan()
        if scan is None:
            return False
        self._attached_scan = scan
        self._clear()
        self._append_line("$ linux_guardian.sh --scan")
        self._append_line("[INFO] Attached to the scan already running — live progress is below.")
        self._append_line(
            f"[INFO] {scan.comm} pid {scan.pid} scanning {scan.target}. "
            "Elapsed time and current file update every half-second."
        )
        self._set_busy(True, "Malware/rootkit scan")
        already = max(0.0, time.time() - scan.start_epoch)
        self._started_at = time.monotonic() - already

        def cancel() -> None:
            # This scan may share gnome-shell's process group (PGID of the
            # session). Never killpg() here — that would signal the desktop.
            for pid in (scan.pid, scan.script_pid):
                if not pid:
                    continue
                try:
                    os.kill(int(pid), signal.SIGTERM)
                except OSError as exc:
                    self._append_line(f"[error] could not stop pid {pid}: {exc}")

        self._cancel = cancel
        if self._attach_tick_id:
            GLib.source_remove(self._attach_tick_id)
        self._attach_tick_id = GLib.timeout_add(500, self._on_attach_tick)
        self._on_attach_tick()
        return True

    def _on_attach_tick(self) -> bool:
        if not self._busy or self._attached_scan is None:
            return False
        snap = snapshot(self._attached_scan)
        if not snap.alive:
            self._append_line("[INFO] Scanner process ended.")
            self._set_busy(False, "Malware/rootkit scan")
            self._finish_progress(0, "Malware/rootkit scan")
            self._cancel = None
            self._attached_scan = None
            self._attach_tick_id = 0
            self._refresh_last_scan()
            return False
        self._apply_progress(
            Progress(
                phase=snap.phase,
                message=(
                    f"{snap.comm} still running · {human_bytes(snap.bytes_read)} read · CPU {snap.cpu_pct}"
                ),
                current=snap.current,
                step=1 if snap.phase == "clamav" else 2,
                steps=2,
            )
        )
        return True

    def _run(self, script: str, args: list[str], label: str, *, unstoppable: bool = False, rootkit: bool = False) -> None:
        self._unstoppable = unstoppable
        self._rootkit_job = rootkit
        if self._attach_tick_id:
            GLib.source_remove(self._attach_tick_id)
            self._attach_tick_id = 0
        self._attached_scan = None
        self._clear()
        self._append_line(f"$ {script} {' '.join(args)}")
        self._set_busy(True, label)

        def on_done(code: int) -> bool:
            if code == 130:
                self._append_line(f"\n[{label} stopped]")
            else:
                self._append_line(f"\n[{label} finished, exit code {code}]")
            self._set_busy(False, label)
            self._finish_progress(code, label)
            self._cancel = None
            if label == "Security audit" and code == 0:
                self._update_score(self._current_lines)
            self._unstoppable = False
            self._rootkit_job = False
            if "scan" in label.lower():
                GLib.timeout_add(400, self._refresh_last_scan)
            if any(word in label.lower() for word in ("scan", "definitions", "baseline", "integrity")):
                GLib.timeout_add(400, self._refresh_health)
            if code == 2:
                self.progress_title.set_label(f"{label} cancelled")
                self.progress_bar.set_text("Cancelled")
                self.remaining_label.set_label("Password prompt dismissed, nothing was changed")
                self._set_remaining_color("omega-dim")
            return False

        self._cancel = run_streaming_async(script, args, self._append_line, on_done)

    def _on_stop_clicked(self, _btn: Gtk.Button) -> None:
        if self._cancel is None:
            return
        self.stop_btn.set_sensitive(False)
        self.progress_subtitle.set_label("Stopping…")
        self._cancel()

    def _update_score(self, lines: list[str]) -> None:
        score = parse_audit_score(lines)
        if score is None:
            return
        self.score_label.set_label(f"{score.percent}%")
        self.score_detail.set_label(
            f"{score.passed} pass, {score.warned} warn, {score.failed} fail (of {score.total} checks). "
            "A warning counts as half."
        )
        for css in ("omega-warning", "omega-critical", "omega-heading"):
            self.score_label.remove_css_class(css)
        if score.failed:
            self.score_label.add_css_class("omega-critical")
        elif score.warned:
            self.score_label.add_css_class("omega-warning")
        else:
            self.score_label.add_css_class("omega-heading")

    def _refresh_last_scan(self) -> bool:
        data = load_last_scan() or ensure_last_scan()
        for css in ("omega-critical", "omega-warning", "omega-heading"):
            self.last_scan_title.remove_css_class(css)
        if not data:
            self.last_scan_title.set_label("No scan saved yet")
            self.last_scan_title.add_css_class("omega-heading")
            self.last_scan_detail.set_label(
                "Run a scan to store the result. Later scans can skip unchanged files."
            )
            self.changed_check.set_active(False)
            return False
        title, detail = format_last_scan(data)
        self.last_scan_title.set_label(title)
        self.last_scan_detail.set_label(detail)
        severity = last_scan_severity(data)
        self.last_scan_title.add_css_class(
            {"critical": "omega-critical", "warning": "omega-warning"}.get(severity, "omega-heading")
        )
        self.changed_check.set_sensitive(True)
        return False

    def _on_scan_clicked(self, _btn: Gtk.Button) -> None:
        args = ["--scan"]
        args.append("--full" if self.full_check.get_active() else "--quick")
        if self.changed_check.get_active():
            args.append("--changed")
        rootkit = self.rootkit_check.get_active()
        if rootkit:
            args.append("--rootkit")
        self._run("linux_guardian.sh", args, "Malware/rootkit scan", rootkit=rootkit)

    def _on_update_defs_clicked(self, _btn: Gtk.Button) -> None:
        self._run("linux_guardian.sh", ["--update"], "Definitions update", unstoppable=True)

    def _confirm_auto_update(self, _btn: Gtk.Button) -> None:
        if self._busy:
            return
        confirm(
            self.get_root(),
            "Turn on automatic virus-definition updates?",
            "This starts ClamAV's background updater and keeps it on after every reboot, so definitions "
            "refresh several times a day without you pressing anything.\n\n"
            "It changes a system service, so your desktop will ask for your password. You can turn it off "
            "again with: sudo systemctl disable --now clamav-freshclam",
            "Turn on",
            lambda: self._run("linux_guardian.sh", ["--enable-auto-update"], "Definitions update", unstoppable=True),
            destructive=False,
        )

    def _confirm_rebuild_integrity(self, _btn: Gtk.Button) -> None:
        if self._busy:
            return
        confirm(
            self.get_root(),
            "Rebuild the file-integrity baseline?",
            "This records your watched files (Documents, shell start-up files, ~/.ssh, autostart entries, "
            "user services and a few /etc files) exactly as they are right now, and from then on reports "
            "anything that differs.\n\nOnly do this if you are happy with how they look today. Run "
            "Check File Integrity first if you want to see what changed. No password needed.",
            "Rebuild baseline",
            lambda: self._run("linux_watchdog.sh", ["--init"], "Integrity baseline"),
            destructive=False,
        )

    def _on_review_baseline(self, _btn: Gtk.Button) -> None:
        if self._busy:
            return

        def done(_code: int, lines: list[str]) -> None:
            try:
                result = json.loads("".join(lines))
            except json.JSONDecodeError:
                result = {"ok": False, "reason": "Could not analyze the last rootkit scan: " + " ".join(lines)[:200],
                          "files": [], "safe_to_refresh": False}
            rows = [(f["explained"], f["path"], f["why"]) for f in result.get("files", [])]
            safe = bool(result.get("safe_to_refresh"))
            review(
                self.get_root(),
                "Rootkit baseline",
                result.get("reason", "") + (
                    "\n\nRefreshing tells rkhunter that the system as it is now is the good one. "
                    "It needs your password." if safe else ""
                ),
                rows,
                "Refresh baseline" if safe else None,
                (lambda: self._run("linux_guardian.sh", ["--refresh-rootkit-baseline"], "Rootkit baseline refresh",
                                   unstoppable=True)) if safe else None,
            )

        run_sync_async("rkhunter_baseline.py", ["--json"], done, timeout=300.0)

    # ---- scanner health ------------------------------------------------
    def _refresh_health(self) -> bool:
        run_sync_async("scanner_health.py", ["--json"], self._on_health, timeout=30.0)
        return False

    def _on_health(self, code: int, lines: list[str]) -> bool:
        child = self.health_card.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.health_card.remove(child)
            child = nxt
        try:
            from scanner_health import describe  # same module the CLI uses; found via scripts.SUITE_DIR

            if code != 0:
                raise RuntimeError(" ".join(lines)[:200] or f"exit {code}")
            rows = describe(json.loads("".join(lines)))
        except Exception as exc:  # noqa: BLE001 - never let a status card break the dashboard
            self.health_card.append(Gtk.Label(label=f"Could not read scanner health: {exc}", xalign=0, wrap=True))
            return False
        css = {"ok": "omega-heading", "warning": "omega-warning", "critical": "omega-critical"}
        for row in rows:
            line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            name = Gtk.Label(label=row["label"], xalign=0, width_chars=20)
            name.add_css_class("omega-dim")
            line.append(name)
            text = Gtk.Label(label=row["text"], xalign=0, wrap=True, hexpand=True)
            text.add_css_class(css.get(row["level"], "omega-dim"))
            line.append(text)
            self.health_card.append(line)
            if row.get("action") == "rebuild_integrity":
                rebuild = Gtk.Button(label="Rebuild integrity baseline…", halign=Gtk.Align.START)
                rebuild.set_tooltip_text("Records the current state of your watched files as the good one.")
                rebuild.connect("clicked", self._confirm_rebuild_integrity)
                self.health_card.append(rebuild)
            if row.get("action") == "review_baseline":
                review_btn = Gtk.Button(label="Review rootkit baseline…", halign=Gtk.Align.START)
                review_btn.set_tooltip_text("Checks each warned file against its Ubuntu package. Changes nothing by itself.")
                review_btn.connect("clicked", self._on_review_baseline)
                self.health_card.append(review_btn)
            if row.get("command"):
                turn_on = Gtk.Button(label="Turn on automatic updates", halign=Gtk.Align.START)
                turn_on.set_tooltip_text(f"Runs: {row['command']} (asks for your password)")
                turn_on.connect("clicked", self._confirm_auto_update)
                self.health_card.append(turn_on)
                hint = Gtk.Label(label=f"Same thing by hand: {row['command']}", xalign=0, selectable=True, wrap=True, margin_start=4)
                hint.add_css_class("omega-dim")
                hint.add_css_class("monospace")
                self.health_card.append(hint)
        return False

    def _on_integrity_clicked(self, _btn: Gtk.Button) -> None:
        self._run("linux_watchdog.sh", ["--check"], "Integrity check")

    def _on_audit_clicked(self, _btn: Gtk.Button | None) -> None:
        self._run("linux_security_audit.sh", [], "Security audit")

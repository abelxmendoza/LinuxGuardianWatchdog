"""Processes page — grouped by what they do, not Unix names.

Default view is subsystems (GNOME Desktop, Firefox, ROS 2, Docker, …)
with impact labels. Expand a group to see individual PIDs, command lines,
and what happens if you stop them. Unknown is never treated as safe.
"""
from __future__ import annotations

from collections import defaultdict
import json

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk, Pango  # noqa: E402

from linuxguardian_ui.process_help import KEEP_RUNNING, CLOSE_EFFECT, END_HELP, FORCE_HELP, GUIDE
from linuxguardian_ui.components import page_header, info_banner
from linuxguardian_ui.clipboard import copy_text  # noqa: E402
from linuxguardian_ui.dialogs import confirm  # noqa: E402
from linuxguardian_ui.process_catalog import friendly_name  # noqa: E402
from linuxguardian_ui.scripts import run_sync_async  # noqa: E402

IMPACT_ORDER = ("close_app", "feature_stops", "desktop_affected", "session_critical", "unknown")
IMPACT_LABELS = {
    "close_app": "Close app",
    "feature_stops": "Feature stops",
    "desktop_affected": "Desktop affected",
    "session_critical": "Don't kill",
    "unknown": "Unknown",
}
IMPACT_CSS = {
    "close_app": "omega-heading",
    "feature_stops": "omega-warning",
    "desktop_affected": "omega-warning",
    "session_critical": "omega-critical",
    "unknown": "omega-dim",
}
SECTION_FOR_GROUP = {
    "close_app": "Programs you opened",
    "feature_stops": "Features & work stacks",
    "desktop_affected": "Desktop helpers",
    "session_critical": "Session & system",
    "unknown": "Unrecognized",
}


def _make_metric_chip(label: str, css_class: str) -> Gtk.Box:
    chip = Gtk.Box(halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER)
    chip.add_css_class("omega-metric")
    chip.add_css_class(css_class)
    chip.append(Gtk.Label(label=label))
    return chip


def _cpu_chip_class(pct: float) -> str:
    if pct > 50:
        return "omega-metric-critical"
    if pct > 20:
        return "omega-metric-warning"
    if pct > 5:
        return "omega-metric-normal"
    return "omega-metric-dim"


def _mem_chip_class(pct: float) -> str:
    if pct > 15:
        return "omega-metric-critical"
    if pct > 5:
        return "omega-metric-warning"
    if pct > 1:
        return "omega-metric-normal"
    return "omega-metric-dim"


class ProcessesPage(Gtk.Box):
    def __init__(self, toast_overlay: Adw.ToastOverlay) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self._toast_overlay = toast_overlay
        self.add_css_class("process-page")
        self.set_margin_top(24)
        self.set_margin_bottom(16)
        self.set_margin_start(24)
        self.set_margin_end(24)

        self._expanded_groups: set[str] = set()
        hero = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        hero.add_css_class("process-hero")
        hero.append(page_header("Your system, at a glance", "Explore running apps. Understand their impact. Stay in control.", "system-run-symbolic"))
        stats = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12, homogeneous=True)
        self._stat_values = []
        for caption in ("APP & SERVICE GROUPS", "PROCESSES SHOWN", "COMBINED CPU", "COMBINED MEMORY"):
            tile = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            tile.add_css_class("process-stat")
            value = Gtk.Label(label="—", xalign=0)
            value.add_css_class("process-stat-value")
            label = Gtk.Label(label=caption, xalign=0)
            label.add_css_class("process-stat-caption")
            tile.append(value)
            tile.append(label)
            stats.append(tile)
            self._stat_values.append(value)
        hero.append(stats)
        self.append(hero)
        self.summary = Gtk.Label(label="Reading running processes…", xalign=0)
        self.summary.add_css_class("omega-dim")

        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        toolbar.add_css_class("process-toolbar")
        self.append(toolbar)

        self.search_entry = Gtk.SearchEntry(hexpand=True, placeholder_text="Search apps, services, or commands…")
        self.search_entry.connect("search-changed", lambda _e: self._render())
        toolbar.append(self.search_entry)

        self.sort_dropdown = Gtk.DropDown.new_from_strings(["CPU %", "Memory %"])
        self.sort_dropdown.connect("notify::selected", lambda *_a: self._render())
        options = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        sort_label = Gtk.Label(label="Sort by")
        sort_label.add_css_class("omega-dim")
        options.append(sort_label)
        options.append(self.sort_dropdown)
        self.sort_dropdown.set_tooltip_text("Sort groups and processes by resource usage")

        refresh_btn = Gtk.Button(label="Refresh")
        refresh_btn.add_css_class("suggested-action")
        refresh_btn.connect("clicked", lambda _b: self.refresh())
        toolbar.append(refresh_btn)

        copy_btn = Gtk.Button(label="Copy All")
        copy_btn.connect("clicked", self._on_copy_all)
        toolbar.append(copy_btn)

        close_all_btn = Gtk.Button(label="Close All Apps")
        close_all_btn.add_css_class("danger-outline")
        close_all_btn.set_tooltip_text(
            "Asks every app under 'Programs you opened' to close (SIGTERM). "
            "Never touches background services, desktop helpers, or system processes."
        )
        close_all_btn.connect("clicked", self._on_close_all_clicked)
        toolbar.append(close_all_btn)

        help_btn = Gtk.Button(label="Process guide")
        help_btn.set_tooltip_text("Learn what to keep running, what closing affects, and how End differs from Force Kill")
        help_btn.connect("clicked", self._show_guide)
        toolbar.append(help_btn)

        self.detail_dropdown = Gtk.DropDown.new_from_strings(["Simple", "Advanced"])
        self.detail_dropdown.connect("notify::selected", lambda *_a: self._render())
        view_label = Gtk.Label(label="Details", margin_start=12)
        view_label.add_css_class("omega-dim")
        options.append(view_label)
        options.append(self.detail_dropdown)
        self.detail_dropdown.set_tooltip_text("Show simple descriptions or advanced process information")


        self.spinner = Gtk.Spinner()
        toolbar.append(self.spinner)

        self.append(info_banner("Impact describes what stops with a process. Unknown processes are never assumed safe to end."))
        filters = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        filters.append(Gtk.Label(label="Impact", margin_start=12))
        self.impact_filter = Gtk.DropDown.new_from_strings(["All impacts"] + [IMPACT_LABELS[k] for k in IMPACT_ORDER])
        self.impact_filter.connect("notify::selected", lambda *_: self._render())
        filters.append(self.impact_filter)
        options.append(filters)
        self.append(options)
        self.append(self.summary)

        scroller = Gtk.ScrolledWindow(vexpand=True)
        self.append(scroller)

        self.content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        scroller.set_child(self.content)

        self._rows: list[dict] = []
        self.refresh()

    # -- data ---------------------------------------------------------------
    def _set_busy(self, busy: bool) -> None:
        if busy:
            self.spinner.start()
        else:
            self.spinner.stop()

    def refresh(self) -> None:
        self._set_busy(True)
        sort_key = "mem" if self.sort_dropdown.get_selected() == 1 else "cpu"
        run_sync_async(
            "linux_process_manager.sh",
            ["--list", "--sort", sort_key],
            self._on_list_done,
            timeout=45.0,
        )

    def _on_list_done(self, code: int, lines: list[str]) -> bool:
        self._set_busy(False)
        self._rows = []
        for line in lines:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            row["cpu"] = float(row.get("cpu") or 0)
            row["mem"] = float(row.get("mem") or 0)
            row["pid"] = int(row.get("pid") or 0)
            row["children"] = int(row.get("children") or 0)
            self._rows.append(row)
        self._render()
        return False

    # -- rendering ------------------------------------------------------------
    def _render(self) -> None:
        while (child := self.content.get_first_child()) is not None:
            self.content.remove(child)

        query = self.search_entry.get_text().strip().lower()
        sort_field = "mem" if self.sort_dropdown.get_selected() == 1 else "cpu"

        def matches(row: dict) -> bool:
            if not query:
                return True
            blob = " ".join(
                str(row.get(k, ""))
                for k in ("comm", "name", "purpose", "cmdline", "exe", "group_title", "origin", "unit")
            ).lower()
            return query in blob

        kernel_count = sum(1 for r in self._rows if r.get("group_id") == "kernel")
        visible = [r for r in self._rows if r.get("group_id") != "kernel" and matches(r)]
        groups = self._groups_from(visible, sort_field)
        selected_impact = self.impact_filter.get_selected()
        if selected_impact:
            groups = [g for g in groups if g["impact"] == IMPACT_ORDER[selected_impact - 1]]
            visible = [member for group in groups for member in group["members"]]
        values = (str(len(groups)), str(len(visible)),
                  f"{sum(r['cpu'] for r in visible):.1f}%",
                  f"{sum(r['mem'] for r in visible):.1f}%")
        for label, value in zip(self._stat_values, values):
            label.set_text(value)
        self.summary.set_text(
            f"Showing {len(groups)} groups · Sorted by {'memory' if sort_field == 'mem' else 'CPU usage'} · Expand a group to explore"
        )
        if not groups:
            empty = Gtk.Label(
                label="No matching processes. Try a different filter." if query or selected_impact
                else "No process data available. Refresh to try again.",
                wrap=True, margin_top=32, margin_bottom=32,
            )
            empty.add_css_class("omega-dim")
            self.content.append(empty)

        by_section: dict[str, list[dict]] = defaultdict(list)
        for group in groups:
            by_section[SECTION_FOR_GROUP.get(group["impact"], "Unrecognized")].append(group)

        section_order = (
            "Programs you opened",
            "Features & work stacks",
            "Desktop helpers",
            "Session & system",
            "Unrecognized",
        )
        for title in section_order:
            items = by_section.get(title)
            if not items:
                continue
            self.content.append(self._build_section(title, items))

        if kernel_count:
            note = Gtk.Label(
                label=(
                    f"+ {kernel_count} kernel threads not shown — managed by Linux itself, "
                    "not useful to end from here."
                ),
                xalign=0,
                wrap=True,
            )
            note.add_css_class("omega-dim")
            self.content.append(note)

    def _groups_from(self, rows: list[dict], sort_field: str) -> list[dict]:
        groups: dict[str, dict] = {}
        for r in rows:
            gid = r.get("group_id") or "unknown"
            g = groups.setdefault(
                gid,
                {
                    "id": gid,
                    "title": r.get("group_title") or gid,
                    "blurb": r.get("group_blurb") or "",
                    "impact": r.get("impact") or "unknown",
                    "members": [],
                    "cpu": 0.0,
                    "mem": 0.0,
                    "pids": [],
                    "comm": r.get("comm", ""),
                },
            )
            # Worst impact in the group wins.
            incoming = r.get("impact") or "unknown"
            current = g.get("impact") or "unknown"
            if incoming not in IMPACT_ORDER:
                incoming = "unknown"
            if current not in IMPACT_ORDER:
                current = "unknown"
            if IMPACT_ORDER.index(incoming) > IMPACT_ORDER.index(current):
                g["impact"] = incoming
            g["members"].append(r)
            g["cpu"] += r["cpu"]
            g["mem"] += r["mem"]
            g["pids"].append(r["pid"])
        for g in groups.values():
            g["members"].sort(key=lambda m: m[sort_field], reverse=True)
        return sorted(groups.values(), key=lambda g: g[sort_field], reverse=True)

    def _build_section(self, title: str, groups: list[dict]) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, valign=Gtk.Align.CENTER)
        header.add_css_class("omega-section-header")
        title_lbl = Gtk.Label(label=title, xalign=0)
        title_lbl.add_css_class("omega-section-title")
        header.append(title_lbl)
        n = len(groups)
        count_lbl = Gtk.Label(label=f"— {n} group{'s' if n != 1 else ''}", xalign=0)
        count_lbl.add_css_class("omega-section-count")
        header.append(count_lbl)
        box.append(header)
        for group in groups:
            box.append(self._build_group_expander(group))
        return box

    def _build_group_expander(self, group: dict) -> Gtk.Widget:
        impact = group["impact"]
        n = len(group["members"])
        expander = Gtk.Expander()
        expander.add_css_class("process-group")
        expander.add_css_class("impact-" + impact)

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16, hexpand=True)
        icon_names = {"close_app": "application-x-executable-symbolic", "feature_stops": "applications-engineering-symbolic",
                      "desktop_affected": "preferences-desktop-symbolic", "session_critical": "security-high-symbolic",
                      "unknown": "dialog-question-symbolic"}
        icon = Gtk.Image.new_from_icon_name(icon_names.get(impact, "dialog-question-symbolic"))
        icon.set_pixel_size(24)
        icon.add_css_class("process-group-icon")
        icon.add_css_class(IMPACT_CSS.get(impact, "omega-dim"))
        header.append(icon)
        identity = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, hexpand=True)
        name = Gtk.Label(label=group["title"], xalign=0, ellipsize=Pango.EllipsizeMode.END)
        name.set_tooltip_text(group["title"])
        name.add_css_class("process-group-name")
        identity.append(name)
        count = Gtk.Label(label=f"{n} process{'es' if n != 1 else ''}", xalign=0)
        count.add_css_class("omega-dim")
        identity.append(count)
        description = Gtk.Label(label=group["blurb"], xalign=0, ellipsize=Pango.EllipsizeMode.END, max_width_chars=40)
        description.set_tooltip_text(group["blurb"])
        description.add_css_class("omega-dim")
        identity.append(description)
        header.append(identity)
        header.append(_make_metric_chip(f"{group['cpu']:.1f}%  CPU", _cpu_chip_class(group["cpu"])))
        header.append(_make_metric_chip(f"{group['mem']:.1f}%  MEM", _mem_chip_class(group["mem"])))
        impact_badge = Gtk.Label(label=IMPACT_LABELS.get(impact, "Unknown"), width_chars=14)
        impact_badge.set_valign(Gtk.Align.CENTER)
        impact_badge.add_css_class("impact-badge")
        impact_badge.add_css_class(IMPACT_CSS.get(impact, "omega-dim"))
        header.append(impact_badge)
        expander.set_label_widget(header)
        expander.set_hexpand(True)
        expander.set_expanded(group["id"] in self._expanded_groups)
        def remember_expansion(widget, _param):
            if widget.get_expanded():
                self._expanded_groups.add(group["id"])
            else:
                self._expanded_groups.discard(group["id"])
        expander.connect("notify::expanded", remember_expansion)

        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_top=8, margin_start=8)
        expander.set_child(inner)

        blurb = Gtk.Label(label=group["blurb"], xalign=0, wrap=True)
        blurb.add_css_class("omega-dim")
        inner.append(blurb)

        impact_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        impact_row.add_css_class("impact-note")
        inner.append(impact_row)
        badge = Gtk.Label(label=IMPACT_LABELS.get(impact, impact))
        badge.add_css_class(IMPACT_CSS.get(impact, "omega-dim"))
        impact_row.append(badge)
        comparison = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        comparison.add_css_class("process-decision")
        inner.append(comparison)
        details = [("If you keep it running", KEEP_RUNNING.get(impact, KEEP_RUNNING["unknown"])),
                   ("If you close it", CLOSE_EFFECT.get(impact, CLOSE_EFFECT["unknown"]))]
        for title, explanation in details:
            heading = Gtk.Label(label=title, xalign=0)
            heading.add_css_class("heading")
            comparison.append(heading)
            text = Gtk.Label(label=explanation, xalign=0, wrap=True, selectable=True)
            text.add_css_class("omega-dim")
            comparison.append(text)
        rec = group["members"][0].get("if_stopped", "")
        if rec:
            text = Gtk.Label(label="For this group: " + rec, xalign=0, wrap=True)
            text.add_css_class(IMPACT_CSS.get(impact, "omega-dim"))
            comparison.append(text)

        if impact == "close_app":
            end_btn = Gtk.Button(label="End app")
            end_btn.set_tooltip_text(END_HELP)
            end_btn.connect("clicked", lambda _b, g=group: self._confirm_kill(g, force=False))
            impact_row.append(end_btn)

        action_help = Gtk.Expander(label="Before ending a process")
        text = Gtk.Label(label=END_HELP + "\n\n" + FORCE_HELP, xalign=0, wrap=True, margin_top=8)
        text.add_css_class("omega-dim")
        action_help.set_child(text)
        inner.append(action_help)
        listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        listbox.add_css_class("process-members")
        for member in group["members"]:
            listbox.append(self._build_member_row(member))
        inner.append(listbox)
        return expander

    def _advanced(self) -> bool:
        return self.detail_dropdown.get_selected() == 1

    def _build_member_row(self, proc: dict) -> Gtk.Widget:
        row = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=2,
            margin_top=8,
            margin_bottom=8,
            margin_start=10,
            margin_end=10,
        )
        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        row.append(top)
        title = Gtk.Label(
            label=f"{proc.get('name') or proc['comm']}",
            xalign=0,
            hexpand=True,
            ellipsize=Pango.EllipsizeMode.END,
        )
        title.set_tooltip_text(proc.get("name") or proc["comm"])
        title.add_css_class("heading")
        top.append(title)
        top.append(_make_metric_chip(f"{proc['cpu']:.1f}%  CPU", _cpu_chip_class(proc["cpu"])))
        top.append(_make_metric_chip(f"{proc['mem']:.1f}%  MEM", _mem_chip_class(proc["mem"])))

        simple = proc.get("purpose") or ""
        if proc.get("listening"):
            simple = (simple + "  ·  listening " + ", ".join(proc["listening"])).strip(" ·")
        detail = Gtk.Label(label=simple, xalign=0, wrap=True)
        detail.add_css_class("omega-dim")
        row.append(detail)

        if self._advanced():
            bits = [
                f"PID {proc['pid']}  PPID {proc.get('ppid', '?')}",
                f"exe: {proc.get('exe') or '(none)'}",
                f"origin: {proc.get('origin') or 'Unknown'}",
                f"parent: {proc.get('parent_comm') or '?'}",
                f"systemd: {proc.get('unit') or '(none)'}",
                f"children: {proc.get('children') or 0}",
            ]
            if proc.get("listening"):
                bits.append("sockets: " + ", ".join(proc["listening"]))
            bits.append(proc.get("recommendation") or "")
            extra = Gtk.Label(label="  ·  ".join(bits), xalign=0, wrap=True)
            extra.add_css_class("process-command")
            extra.set_selectable(True)
            row.append(extra)
            if proc.get("cmdline"):
                cmd = Gtk.Label(label=proc["cmdline"], xalign=0, wrap=True)
                cmd.add_css_class("process-command")
                cmd.set_selectable(True)
                row.append(cmd)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, halign=Gtk.Align.END)
        actions.add_css_class("process-actions")
        row.append(actions)
        group = {
            "comm": proc["comm"],
            "kind": proc.get("kind", "system"),
            "impact": proc.get("impact", "unknown"),
            "pids": [proc["pid"]],
            "title": proc.get("name") or proc["comm"],
        }
        end_btn = Gtk.Button(label="End")
        end_btn.set_tooltip_text(END_HELP)
        end_btn.connect("clicked", lambda _b, g=group: self._confirm_kill(g, force=False))
        actions.append(end_btn)
        force_btn = Gtk.Button(label="Force Kill")
        force_btn.set_tooltip_text(FORCE_HELP)
        force_btn.add_css_class("danger-outline")
        force_btn.connect("clicked", lambda _b, g=group: self._confirm_kill(g, force=True))
        actions.append(force_btn)
        return row

    # -- close-all (safe) -------------------------------------------------
    def _safe_kill_all_groups(self) -> list[dict]:
        """Return only groups that are safe to bulk-close.

        Rules that can never be relaxed:
        - impact must be 'close_app' — anything else is off-limits
        - LinuxGuardian itself is excluded (killing the UI mid-action is bad UX)
        Kernel threads are already filtered out by _groups_from callers.
        """
        sort_field = "mem" if self.sort_dropdown.get_selected() == 1 else "cpu"
        groups = self._groups_from(
            [r for r in self._rows if r.get("group_id") != "kernel"], sort_field
        )
        return [g for g in groups if g["impact"] == "close_app" and g["id"] != "linuxguardian"]

    def _on_close_all_clicked(self, _btn: Gtk.Button) -> None:
        groups = self._safe_kill_all_groups()
        if not groups:
            self._toast_overlay.add_toast(Adw.Toast(title="No open apps to close", timeout=2))
            return
        total_procs = sum(len(g["pids"]) for g in groups)
        name_list = ", ".join(g["title"] for g in groups)
        confirm(
            self.get_root(),
            f"Close {len(groups)} open app{'s' if len(groups) != 1 else ''}?",
            f"This asks each app to close gracefully (same as clicking End on each one). "
            f"Apps: {name_list}. "
            f"{total_procs} process{'es' if total_procs != 1 else ''} total.\n\n"
            "Background services, desktop helpers, and system processes are never touched.",
            confirm_label="Close Apps",
            on_confirm=lambda: self._do_close_all(groups),
            destructive=True,
        )

    def _do_close_all(self, groups: list[dict]) -> None:
        pid_to_group: dict[int, dict] = {pid: g for g in groups for pid in g["pids"]}
        remaining = len(pid_to_group)
        if remaining == 0:
            return
        failed_titles: set[str] = set()

        def on_one_done(pid: int, code: int, _lines: list[str]) -> bool:
            nonlocal remaining
            if code != 0:
                failed_titles.add(pid_to_group[pid]["title"])
            remaining -= 1
            if remaining == 0:
                if failed_titles:
                    msg = (
                        f"Closed {len(groups) - len(failed_titles)} of {len(groups)} apps — "
                        f"{', '.join(sorted(failed_titles))} needed sudo or failed"
                    )
                else:
                    msg = f"Closed {len(groups)} app{'s' if len(groups) != 1 else ''}"
                self._toast_overlay.add_toast(Adw.Toast(title=msg, timeout=4))
                self.refresh()
            return False

        for pid in pid_to_group:
            run_sync_async(
                "linux_process_manager.sh",
                ["--kill", str(pid)],
                lambda c, l, p=pid: on_one_done(p, c, l),
            )

    # -- actions ----------------------------------------------------------
    def _show_guide(self, _button: Gtk.Button) -> None:
        dialog = Gtk.Window(title="Understanding processes", transient_for=self.get_root(), modal=True)
        dialog.set_default_size(620, 620)
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16,
                       margin_top=20, margin_bottom=20, margin_start=20, margin_end=20)
        dialog.set_child(root)
        root.append(page_header("Understand before you end", "A practical guide to apps, helpers, and system services.", "dialog-information-symbolic"))
        scroller = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        root.append(scroller)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        scroller.set_child(content)
        for title, explanation in GUIDE:
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            card.add_css_class("process-decision")
            heading = Gtk.Label(label=title, xalign=0)
            heading.add_css_class("heading")
            card.append(heading)
            card.append(Gtk.Label(label=explanation, xalign=0, wrap=True, selectable=True))
            content.append(card)
        close = Gtk.Button(label="Got it", halign=Gtk.Align.END)
        close.add_css_class("suggested-action")
        close.connect("clicked", lambda _b: dialog.close())
        root.append(close)
        dialog.present()

    def _on_copy_all(self, _btn: Gtk.Button) -> None:
        if not self._rows:
            self._toast_overlay.add_toast(Adw.Toast(title="Nothing to copy yet", timeout=2))
            return
        try:
            copy_text(self._list_as_text())
        except Exception as exc:  # noqa: BLE001
            self._toast_overlay.add_toast(Adw.Toast(title=f"Copy failed: {exc}", timeout=3))
            return
        self._toast_overlay.add_toast(Adw.Toast(title="Process list copied", timeout=2))

    def _list_as_text(self) -> str:
        sort_field = "mem" if self.sort_dropdown.get_selected() == 1 else "cpu"
        groups = self._groups_from(
            [r for r in self._rows if r.get("group_id") != "kernel"], sort_field
        )
        lines = [
            "LinuxGuardian Watchdog — grouped process list",
            "Please explain each group, whether it is safe to stop, and anything unusual.",
            "Impact: Close app / Feature stops / Desktop affected / Don't kill / Unknown.",
            "Unknown is never assumed safe.",
            "",
        ]
        for group in groups:
            lines.append(
                f"## {group['title']}  ({len(group['members'])} processes, "
                f"{group['cpu']:.1f}% CPU, {IMPACT_LABELS.get(group['impact'])})"
            )
            lines.append(group["blurb"])
            lines.append(f"If stopped: {group['members'][0].get('if_stopped', '')}")
            for m in group["members"]:
                listen = ",".join(m.get("listening") or [])
                lines.append(f"- {m.get('name') or m['comm']}  ({m['cpu']:.1f}% CPU)")
                if m.get("purpose"):
                    lines.append(f"  {m['purpose']}")
                if listen:
                    lines.append(f"  listening: {listen}")
                if self._advanced():
                    lines.append(
                        f"  PID {m['pid']} PPID {m.get('ppid')}  exe={m.get('exe')}  "
                        f"origin={m.get('origin')}  parent={m.get('parent_comm')}  "
                        f"unit={m.get('unit')}  children={m.get('children')}"
                    )
                    if m.get("cmdline"):
                        lines.append(f"  cmdline: {m['cmdline']}")
            lines.append("")
        kernel_count = sum(1 for r in self._rows if r.get("group_id") == "kernel")
        if kernel_count:
            lines.append(f"+ {kernel_count} kernel threads omitted.")
        return "\n".join(lines).rstrip() + "\n"

    def _confirm_kill(self, group: dict, force: bool) -> None:
        root = self.get_root()
        name = group.get("title") or friendly_name(group.get("comm", "process"))
        verb = "Force kill" if force else "End"
        count = len(group["pids"])
        subject = f"{name} ({count} processes)" if count > 1 else name
        impact = group.get("impact") or "unknown"

        body_parts = [
            FORCE_HELP if force else END_HELP,
            f"This will {'immediately terminate (SIGKILL)' if force else 'ask to close (SIGTERM)'} {subject}."
        ]
        if impact == "session_critical":
            body_parts.append("⚠ Don't kill — this can crash your session or drop the network.")
        elif impact == "desktop_affected":
            body_parts.append("Desktop helpers may break (files, settings, portals, typing).")
        elif impact == "unknown":
            body_parts.append("LinuxGuardian does not recognize this. Do not assume it is safe.")
        elif impact == "feature_stops":
            body_parts.append("A feature will stop (ROS, Docker, calendar, remote desktop, …).")

        confirm(
            root,
            f"{verb} {name}?",
            " ".join(body_parts),
            confirm_label=verb,
            on_confirm=lambda: self._do_kill(group, force),
            destructive=True,
        )

    def _do_kill(self, group: dict, force: bool) -> None:
        pids = list(group["pids"])
        remaining = len(pids)
        results = {"failed": 0}

        def on_one_done(code: int, _lines: list[str]) -> bool:
            nonlocal remaining
            if code != 0:
                results["failed"] += 1
            remaining -= 1
            if remaining == 0:
                name = group.get("title") or friendly_name(
                    group.get("comm", "process"),
                    str(group.get("pid", "")),
                    group.get("cmdline", ""),
                    group.get("exe", ""),
                    group.get("kind", "system"),
                )
                if results["failed"]:
                    message = f"Ended {name}, but {results['failed']} process(es) needed sudo or failed"
                else:
                    message = f"Ended {name}"
                self._toast_overlay.add_toast(Adw.Toast(title=message, timeout=3))
                self.refresh()
            return False

        for pid in pids:
            args = ["--kill", str(pid)]
            if force:
                args.append("--force")
            run_sync_async("linux_process_manager.sh", args, on_one_done)

"""Minimal confirm dialog.

Adw.MessageDialog needs libadwaita >= 1.2, which isn't available on every
target (e.g. Ubuntu 22.04 ships 1.1). This is a small hand-rolled
replacement built from plain Gtk.Window so it works everywhere GTK4 does.
"""
from __future__ import annotations

from collections.abc import Callable

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402


def confirm(
    parent: Gtk.Window,
    heading: str,
    body: str,
    confirm_label: str,
    on_confirm: Callable[[], None],
    destructive: bool = True,
) -> None:
    dialog = Gtk.Window(transient_for=parent, modal=True, title=heading)
    dialog.set_default_size(360, -1)
    dialog.set_resizable(False)

    box = Gtk.Box(
        orientation=Gtk.Orientation.VERTICAL,
        spacing=16,
        margin_top=20,
        margin_bottom=20,
        margin_start=20,
        margin_end=20,
    )
    dialog.set_child(box)

    heading_label = Gtk.Label(label=heading, wrap=True, xalign=0)
    heading_label.add_css_class("omega-heading")
    heading_label.add_css_class("title-3")
    box.append(heading_label)

    body_label = Gtk.Label(label=body, wrap=True, xalign=0)
    box.append(body_label)

    button_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, halign=Gtk.Align.END)
    box.append(button_row)

    cancel_btn = Gtk.Button(label="Cancel")
    cancel_btn.connect("clicked", lambda _b: dialog.close())
    button_row.append(cancel_btn)

    confirm_btn = Gtk.Button(label=confirm_label)
    confirm_btn.add_css_class("destructive-action" if destructive else "suggested-action")

    def _on_confirm_clicked(_btn: Gtk.Button) -> None:
        dialog.close()
        on_confirm()

    confirm_btn.connect("clicked", _on_confirm_clicked)
    button_row.append(confirm_btn)

    dialog.present()

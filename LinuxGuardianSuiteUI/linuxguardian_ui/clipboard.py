"""Copy plain text to the desktop clipboard (GTK4)."""
from __future__ import annotations

import gi

gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, GLib  # noqa: E402


def copy_text(text: str) -> None:
    display = Gdk.Display.get_default()
    if display is None:
        raise RuntimeError("no display")
    clipboard = display.get_clipboard()
    provider = Gdk.ContentProvider.new_for_bytes(
        "text/plain;charset=utf-8",
        GLib.Bytes.new(text.encode("utf-8")),
    )
    clipboard.set_content(provider)

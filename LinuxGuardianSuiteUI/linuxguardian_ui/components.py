"""Native GTK counterparts to MacGuardian's section headers and alert banners."""
from __future__ import annotations

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gdk, GLib, Gtk

RESOURCES = Path(__file__).resolve().parents[1] / "resources"
LOGO_MARK = RESOURCES / "logo-mark.png"       # the wolf, 96px, for in-app use
LOGO_FULL = RESOURCES.parents[1] / "images" / "LinuxGuardianLogo.png"


def brand_image(size: int, fallback_icon: str = "security-high-symbolic") -> Gtk.Widget:
    """The wolf mark at `size` px; a themed icon if the file is missing (never crash the UI over a logo)."""
    if LOGO_MARK.is_file():
        try:
            # GtkImage + pixel-size gives a hard size; GtkPicture would grow to the file's natural 96px.
            logo = Gtk.Image.new_from_paintable(Gdk.Texture.new_from_filename(str(LOGO_MARK)))
            logo.set_pixel_size(size)
            logo.set_halign(Gtk.Align.CENTER)
            logo.set_valign(Gtk.Align.CENTER)
            logo.add_css_class("brand-mark")
            return logo
        except GLib.Error:
            pass
    image = Gtk.Image.new_from_icon_name(fallback_icon)
    image.set_pixel_size(size)
    return image


def brand_lockup() -> Gtk.Widget:
    """Header bar brand: wolf + 'LinuxGuardian' (purple) over 'WATCHDOG' (orange), like the logo."""
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    box.append(brand_image(30))
    text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0, valign=Gtk.Align.CENTER)
    name = Gtk.Label(label="LinuxGuardian", xalign=0)
    name.add_css_class("brand-name")
    sub = Gtk.Label(label="WATCHDOG", xalign=0)
    sub.add_css_class("brand-sub")
    text.append(name)
    text.append(sub)
    box.append(text)
    return box


def page_header(title: str, subtitle: str, icon: str, *, logo: bool = False) -> Gtk.Widget:
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
    if logo:
        box.append(brand_image(56, icon))
    else:
        image = Gtk.Image.new_from_icon_name(icon)
        image.set_pixel_size(32)
        image.add_css_class("omega-heading")
        box.append(image)
    text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, hexpand=True)
    heading = Gtk.Label(label=title, xalign=0)
    heading.add_css_class("title-1")
    text.append(heading)
    detail = Gtk.Label(label=subtitle, xalign=0, wrap=True)
    detail.add_css_class("omega-dim")
    text.append(detail)
    box.append(text)
    return box


def section_header(title: str) -> Gtk.Widget:
    label = Gtk.Label(label=title, xalign=0, margin_top=8)
    label.add_css_class("heading")
    return label


def info_banner(message: str) -> Gtk.Widget:
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
    box.add_css_class("guardian-banner")
    box.append(Gtk.Image.new_from_icon_name("dialog-information-symbolic"))
    box.append(Gtk.Label(label=message, xalign=0, wrap=True, hexpand=True))
    return box


def copy_action(label, get_text):
    """Copy current data on click, with visible success, empty, and failure feedback."""
    from linuxguardian_ui.clipboard import copy_text
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    button = Gtk.Button(label=label)
    status = Gtk.Label(label="", wrap=True)
    status.add_css_class("omega-dim")
    button.set_tooltip_text("Copies plain text. Reports may include local paths and commands; review before sharing.")
    def clicked(_button):
        try:
            text = get_text()
            if not text:
                status.set_text("Nothing to copy yet")
                return
            copy_text(text)
            status.set_text("Copied")
        except Exception as exc:
            status.set_text(f"Copy failed: {exc}")
    button.connect("clicked", clicked)
    box.append(button)
    box.append(status)
    return box


def report_window(parent, title, text):
    """Scrollable, selectable terminal-style report with a Copy All action."""
    window = Gtk.Window(title=title, transient_for=parent, modal=True)
    window.set_default_size(760, 560)
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12,
                  margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
    window.set_child(box)
    box.append(copy_action("Copy All", lambda: text))
    scroller = Gtk.ScrolledWindow(vexpand=True, hexpand=True)
    view = Gtk.TextView(editable=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
    view.get_buffer().set_text(text or "No output captured yet.")
    scroller.set_child(view)
    box.append(scroller)
    close = Gtk.Button(label="Close", halign=Gtk.Align.END)
    close.connect("clicked", lambda _b: window.close())
    box.append(close)
    window.present()
    return window


def widget_report(widget, title="Page report"):
    """Copy rendered page text, including collapsed details, without triggering actions."""
    from linuxguardian_ui.reports import timestamp
    lines = [f"LinuxGuardian — {title}", f"Captured: {timestamp()}",
             "Scope: current page text, including collapsed technical details. Not a new check.", ""]
    def visit(node):
        if isinstance(node, (Gtk.Button, Gtk.DropDown)):
            return
        if isinstance(node, Gtk.Label):
            text = node.get_text().strip()
            if text:
                is_heading = any(node.has_css_class(c) for c in ("heading", "title-1", "title-2", "title-3", "title-4", "activity-title", "activity-group-title", "update-name", "omega-heading"))
                lines.append(("\n## " if is_heading else "") + text)
        elif isinstance(node, Gtk.TextView):
            buffer = node.get_buffer()
            lines.extend(["\n## Terminal / technical output", buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), True)])
            return
        child = node.get_first_child()
        while child:
            visit(child)
            child = child.get_next_sibling()
    visit(widget)
    return "\n".join(lines) + "\n"

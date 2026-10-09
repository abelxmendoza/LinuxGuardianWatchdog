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

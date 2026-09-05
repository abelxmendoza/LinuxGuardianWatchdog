"""Native GTK counterparts to MacGuardian's section headers and alert banners."""
from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


def page_header(title: str, subtitle: str, icon: str) -> Gtk.Widget:
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
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

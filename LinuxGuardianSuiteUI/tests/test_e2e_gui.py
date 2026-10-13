"""End to end through the real GTK window: start-up, every tab, and real page workflows backed by the real scripts.

Needs a display. Locally that is your desktop; in CI it is xvfb (`xvfb-run -a pytest`). Without one these tests skip themselves.
Everything runs in a disposable home with a stand-in virus scanner: no live malware, no real firewall or process is touched.
"""
from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "LinuxGuardianSuite"
sys.path.insert(0, str(SUITE))
sys.path.insert(0, str(ROOT / "LinuxGuardianSuiteUI"))

gi = pytest.importorskip("gi")
try:
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk
except (ValueError, ImportError) as exc:                       # pragma: no cover - environment without GTK4/libadwaita
    pytest.skip(f"GTK4/libadwaita not available: {exc}", allow_module_level=True)

if not Gtk.init_check():                                      # no display
    pytest.skip("no display (run with xvfb-run -a)", allow_module_level=True)

import audit_events  # noqa: E402
import events  # noqa: E402
from test_e2e_workflows import CLAMSCAN, MARKER  # noqa: E402

from linuxguardian_ui import crashlog  # noqa: E402
import linuxguardian_ui.main as app_main  # noqa: E402
import linuxguardian_ui.window as window_mod  # noqa: E402
from linuxguardian_ui.pages.health_window import HealthWindow  # noqa: E402
from linuxguardian_ui.pages.terminal_window import TerminalWindow  # noqa: E402

TABS = ["dashboard", "hardening", "vpn", "processes", "cache", "updates", "exposure", "apps", "incidents", "malware"]


def pump(seconds: float = 0.0, until=None, timeout: float = 20.0) -> bool:
    """Run the GTK main loop: for a fixed time, or until a condition is true (returns whether it became true)."""
    ctx = GLib.MainContext.default()
    end = time.monotonic() + (seconds if until is None else timeout)
    while time.monotonic() < end:
        while ctx.iteration(False):
            pass
        if until is not None and until():
            return True
        time.sleep(0.02)
    return until() if until else True


def walk(widget):
    yield widget
    child = widget.get_first_child()
    while child is not None:
        yield from walk(child)
        child = child.get_next_sibling()


def labels(widget) -> list[str]:
    out = []
    for w in walk(widget):
        if isinstance(w, Gtk.Label) and w.get_label():
            out.append(w.get_label())
        elif isinstance(w, Gtk.Button) and w.get_label():
            out.append(w.get_label())
    return out


def buttons(widget, text: str) -> list[Gtk.Button]:
    return [w for w in walk(widget) if isinstance(w, Gtk.Button) and (w.get_label() or "") == text]


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    t = tmp_path_factory.mktemp("gui")
    mp = pytest.MonkeyPatch()
    for d in ("home/Downloads", "home/Documents", "bin", "etc", "su", "approot"):
        (t / d).mkdir(parents=True)
    scanner = t / "bin" / "clamscan"
    scanner.write_text(CLAMSCAN)
    scanner.chmod(scanner.stat().st_mode | stat.S_IEXEC)
    for n, body in (("clamdscan", "exit 2"), ("rkhunter", "exit 0"), ("freshclam", "exit 0"), ("systemctl", "exit 3"), ("dpkg", "echo no >&2; exit 1"),
                    ("pkexec", f'echo "pkexec $*" >> "{t}/escalations.log"; exit 126'), ("notify-send", "exit 0")):
        p = t / "bin" / n
        p.write_text("#!/bin/sh\n" + body + "\n")
        p.chmod(0o755)
    home = Path(os.environ["HOME"])                                           # the session's throwaway home (see conftest)
    lg = Path(os.environ["LG_HOME"])
    mp.setenv("PATH", f"{t / 'bin'}:/usr/bin:/bin")
    mp.setenv("LG_SENSOR_HOME", str(home))
    mp.setenv("LG_SENSOR_ETC", str(t / "etc"))
    mp.setenv("LG_SETUID_ROOTS", str(t / "su"))
    mp.setenv("LG_APP_ROOT", str(t / "approot"))
    mp.setenv("LG_UFW_CONF", str(t / "no-ufw.conf"))
    mp.setenv("LG_NOTIFY_CMD", str(t / "bin" / "notify-send"))
    # seeded state: an infected file the "last scan" found, and a standing audit finding plus an incident
    infected = home / "Downloads" / "setup_helper.bin"
    infected.parent.mkdir(parents=True, exist_ok=True)
    infected.write_text(f"#!/bin/sh\n# {MARKER}\n")
    infected.chmod(0o755)
    (lg / "scans").mkdir(parents=True, exist_ok=True)
    report = lg / "scans" / "clam.log"
    report.write_text(f"{infected}: Test.Stub-Signature FOUND\n----------- SCAN SUMMARY -----------\nInfected files: 1\n")
    (lg / "scans" / "last.json").write_text(json.dumps({"report": str(report), "infected": 1, "timestamp": "2026-10-12T10:00:00"}))
    audit_events.process([("warning", "No LUKS-encrypted volume detected — consider full-disk encryption")])
    events.record_event("sensor", "warning", "proc_from_tmp", "A program is running from a temporary folder: /tmp/.x/payload (as you).",
                        entity=["/tmp/.x/payload"], technique="T1036", stage="execution", key="gui1", sensor="processes")
    errors: list[tuple] = []
    old_hook = sys.excepthook
    sys.excepthook = lambda *a: errors.append(a)                              # callbacks that raise inside GLib land here
    app_main._load_omega_theme()
    app = Adw.Application(application_id="org.linuxguardian.E2E")
    app.register(None)
    win = window_mod.LinuxGuardianWindow(app)
    win.set_default_size(1280, 800)
    win.present()
    pump(3.0)
    yield {"app": app, "win": win, "errors": errors, "home": home, "lg": lg, "infected": infected, "tmp": t}
    sys.excepthook = old_hook
    win.destroy()
    mp.undo()                                                              # this module's own MonkeyPatch, not the shared fixture


# ================================================================================ start-up and tabs
def test_the_application_starts_and_every_tab_exists(world):
    win = world["win"]
    assert win.is_visible() and "LinuxGuardian" in win.get_title()
    names = [p.get_name() for p in win.view_stack.get_pages()]
    assert names == TABS
    assert all(win.view_stack.get_child_by_name(n) is not None for n in TABS)


def test_every_tab_opens_without_an_error_card_or_an_exception(world):
    win = world["win"]
    for name in TABS:
        win.view_stack.set_visible_child_name(name)
        pump(0.8)
        assert win.view_stack.get_visible_child_name() == name
        page = win.view_stack.get_child_by_name(name)
        assert not [l for l in labels(page) if "couldn't load" in l], f"{name} tab failed to build"
    assert world["errors"] == [], [str(e[1]) for e in world["errors"]]
    assert not crashlog.log_path().exists()                                  # nothing was written to the crash log


def test_the_startup_health_check_reports_through_the_title_bar_button(world):
    win = world["win"]
    assert pump(until=lambda: any(c in win.health_btn.get_css_classes() for c in ("success", "warning", "error")), timeout=30)
    assert "LinuxGuardian health:" in win.health_btn.get_tooltip_text()


# ====================================================================================== malware tab
def test_the_malware_tab_lists_a_finding_and_quarantines_it_through_the_real_script(world):
    win = world["win"]
    win.view_stack.set_visible_child_name("malware")
    page = win.view_stack.get_child_by_name("malware")
    page.refresh()
    assert pump(until=lambda: any("setup_helper.bin" in l for l in labels(page)), timeout=60), labels(page)[:20]
    assert any("Test.Stub-Signature" in l for l in labels(page)) and buttons(page, "Move to quarantine")
    page._quarantine({"path": str(world["infected"]), "signature": "Test.Stub-Signature"})                # what the confirmed button does
    assert pump(until=lambda: not world["infected"].exists(), timeout=60)
    assert pump(until=lambda: buttons(page, "Restore") and buttons(page, "Delete permanently…"), timeout=60)
    assert any("From" in l and "setup_helper.bin" in l for l in labels(page))
    assert world["errors"] == []


# ===================================================================================== timeline tab
def test_accepting_a_risk_from_the_timeline_keeps_it_visible_and_leaves_the_incident_alone(world):
    win = world["win"]
    win.view_stack.set_visible_child_name("incidents")
    pump(0.5)
    inc_page = win.view_stack.get_child_by_name("incidents")
    toggle = [w for w in walk(inc_page) if isinstance(w, Gtk.ToggleButton) and w.get_label() == "All events (timeline)"][0]
    toggle.set_active(True)
    pump(1.0)
    tl = inc_page.timeline
    shown = labels(tl)
    assert any("LUKS" in l for l in shown) and any("temporary folder" in l for l in shown)
    assert any("Possible incident" in l for l in shown) and any(l.startswith("Finding") for l in shown)
    accept = buttons(tl, "Accept this risk")
    assert accept                                                                       # offered for the audit finding, not for the incident
    import timeline as tmod
    entry = next(e for e in tmod.load_entries() if "LUKS" in e.message and e.category == "audit" and e.severity == "warning")
    tl._do_accept(entry)
    assert audit_events.is_accepted(entry.message)
    tl.show_seen.set_active(True)
    assert pump(until=lambda: buttons(tl, "Stop accepting"), timeout=10)
    assert any(l == "Accepted" for l in labels(tl))
    assert any("temporary folder" in l for l in labels(tl))                             # the unrelated incident is still there
    tl._on_unaccept(None, entry)
    assert not audit_events.is_accepted(entry.message)
    assert pump(until=lambda: buttons(tl, "Accept this risk"), timeout=10)              # the original behaviour is back
    assert world["errors"] == []


def test_the_incidents_status_card_shows_monitoring_threat_lists_and_decoys(world):
    win = world["win"]
    win.view_stack.set_visible_child_name("incidents")
    inc_page = win.view_stack.get_child_by_name("incidents")
    toggle = [w for w in walk(inc_page) if isinstance(w, Gtk.ToggleButton) and w.get_label() == "Incidents"][0]
    toggle.set_active(True)
    inc_page.incidents.refresh()
    assert pump(until=lambda: any("Known-bad addresses" in l for l in labels(inc_page.incidents)) and any("Decoy files" in l for l in labels(inc_page.incidents)), timeout=60)
    assert any("Live monitoring" in l for l in labels(inc_page.incidents))
    assert buttons(inc_page.incidents, "Check now") and buttons(inc_page.incidents, "Plant decoys…")


def test_the_coverage_view_builds_a_card_for_every_technique(world):
    win = world["win"]
    inc_page = win.view_stack.get_child_by_name("incidents")
    toggle = [w for w in walk(inc_page) if isinstance(w, Gtk.ToggleButton) and w.get_label() == "What it can notice"][0]
    toggle.set_active(True)
    assert pump(until=lambda: sum(1 for l in labels(inc_page.coverage) if "Covered" == l or "Partly" == l or "Not covered" == l or "Turned off" == l) >= 40, timeout=60)
    assert any("not covered" in l.lower() for l in labels(inc_page.coverage))


# ================================================================ terminal commands and health windows
def test_the_terminal_commands_window_searches_and_validates_values(world):
    tw = TerminalWindow(world["win"], None)
    tw.present()
    pump(0.5)
    cards = [c for c, _t, is_group in tw._cards if not is_group]
    assert len(cards) >= 25 and all(c.get_visible() for c in cards)
    tw.search.set_text("quarantine")
    pump(0.3)
    visible = [c for c, _t, g in tw._cards if not g and c.get_visible()]
    assert 0 < len(visible) < len(cards)
    tw.search.set_text("")
    pump(0.3)
    assert all(c.get_visible() for c, _t, g in tw._cards if not g)
    entry = next(w for w in walk(tw) if isinstance(w, Gtk.Entry) and w.get_placeholder_text() and "process id" in w.get_placeholder_text())
    card_buttons = [b for b in walk(entry.get_parent()) if isinstance(b, Gtk.Button)]
    entry.set_text("1; reboot")
    assert not any(b.get_sensitive() for b in card_buttons)                              # an invalid value can never be opened
    entry.set_text("4242")
    assert all(b.get_sensitive() for b in card_buttons)
    tw.destroy()


def test_the_health_window_runs_the_real_self_check_and_shows_every_area(world):
    got: list[dict] = []
    hw = HealthWindow(world["win"], None, on_result=got.append)
    hw.present()
    assert pump(until=lambda: bool(got), timeout=60)
    titles = " ".join(labels(hw))
    for area in ("App files", "Who can change the app", "Who can read your LinuxGuardian data", "Live monitoring", "Saving findings"):
        assert area in titles, area
    assert got[0]["level"] in ("ok", "info", "warning", "critical") and got[0]["headline"]
    hw.destroy()


# ========================================================================================== failure
def test_a_tab_that_cannot_be_built_shows_what_happened_and_the_rest_still_works(world, monkeypatch):
    class Boom:
        def __init__(self, *a, **k):
            raise RuntimeError("demo failure: could not read settings")

    monkeypatch.setattr(window_mod, "VpnPage", Boom)
    win2 = window_mod.LinuxGuardianWindow(world["app"])
    win2.present()
    pump(1.0)
    vpn = win2.view_stack.get_child_by_name("vpn")
    text = labels(vpn)
    assert any("VPN tab couldn't load" in l for l in text) and any("RuntimeError: demo failure" in l for l in text)
    assert buttons(vpn, "Use the terminal commands instead") and buttons(vpn, "Check LinuxGuardian's health")
    log = crashlog.log_path().read_text()
    assert "building the VPN tab" in log and "demo failure" in log
    win2.view_stack.set_visible_child_name("malware")                                  # another tab still builds and opens
    pump(0.5)
    assert not [l for l in labels(win2.view_stack.get_child_by_name("malware")) if "couldn't load" in l]
    win2.destroy()
    crashlog.log_path().unlink()

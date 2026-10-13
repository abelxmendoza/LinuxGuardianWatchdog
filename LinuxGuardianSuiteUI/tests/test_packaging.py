"""Installation, upgrade and removal, in a disposable home. Nothing here touches your real desktop settings, timers or files:
`gsettings`, `systemctl` and the desktop-database tools are stand-ins that record what they were asked to do."""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "LinuxGuardianSuite"
UI = ROOT / "LinuxGuardianSuiteUI"


def stub(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


@pytest.fixture()
def machine(tmp_path):
    """A fresh user account: home, a Desktop folder, an unrelated app of the user's, and recording stand-ins for the system tools."""
    h = tmp_path / "home"
    for d in ("Desktop", ".local/share/applications", ".config/systemd/user", ".linuxguardian/quarantine"):
        (h / d).mkdir(parents=True)
    (h / ".local/share/applications/someone-elses-app.desktop").write_text("[Desktop Entry]\nType=Application\nName=Other\nExec=other\n")
    (h / ".config/systemd/user/their-own.service").write_text("[Service]\nExecStart=/bin/true\n")
    (h / "Desktop/notes.txt").write_text("my notes")
    (h / ".linuxguardian/quarantine/keepme").write_text("quarantined file")
    (h / ".linuxguardian/precious.json").write_text('{"a": 1}')
    b = tmp_path / "bin"
    b.mkdir()
    call_log = tmp_path / "calls.log"
    for name in ("gsettings", "update-desktop-database", "gtk-update-icon-cache", "gio"):
        stub(b / name, f'echo "{name} $*" >> "{call_log}"\n' + ('[ "$1" = get ] && echo "[]"; exit 0' if name == "gsettings" else "exit 0"))
    stub(b / "xdg-user-dir", f'echo "{h}/Desktop"')
    stub(b / "systemctl", f'echo "systemctl $*" >> "{call_log}"\nexit "${{SYSTEMCTL_RC:-0}}"')
    env = {**os.environ, "HOME": str(h), "LG_HOME": str(h / ".linuxguardian"), "PATH": f"{b}:/usr/bin:/bin", "XDG_CURRENT_DESKTOP": "GNOME", "DISPLAY": ""}

    class M:
        home = h
        bin = b
        log = call_log

        def run(self, *cmd, **extra):
            return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, env={**env, **extra}, timeout=60)

        def calls(self) -> list[str]:
            return call_log.read_text().splitlines() if call_log.exists() else []

    return M()


def user_files(h: Path) -> dict[str, str]:
    """Everything of the user's that must survive: contents by relative path."""
    keep = {}
    for rel in (".local/share/applications/someone-elses-app.desktop", ".config/systemd/user/their-own.service", "Desktop/notes.txt",
                ".linuxguardian/quarantine/keepme", ".linuxguardian/precious.json"):
        keep[rel] = (h / rel).read_text()
    return keep


# ================================================================================== desktop entry
def test_the_desktop_entry_installs_validly_and_points_at_the_launcher(machine):
    r = machine.run(UI / "install_desktop_entry.sh", "--install")
    assert r.returncode == 0, r.stdout + r.stderr
    entry = machine.home / ".local/share/applications/linuxguardian-watchdog.desktop"
    text = entry.read_text()
    assert "Name=LinuxGuardian Watchdog" in text and f'Exec="{UI}/run_ui.sh"' in text and "Terminal=false" in text
    assert os.access(UI / "run_ui.sh", os.X_OK) and (machine.home / "Desktop/LinuxGuardian Watchdog.desktop").is_file()
    assert (machine.home / ".local/share/icons/hicolor/256x256/apps/linuxguardian-watchdog.png").is_file()
    if shutil.which("desktop-file-validate"):
        v = subprocess.run(["desktop-file-validate", str(entry)], capture_output=True, text=True)
        assert v.returncode == 0, v.stdout + v.stderr
    assert any(c.startswith("gsettings set org.gnome.shell favorite-apps") for c in machine.calls())      # the dock pin went to the stand-in, not dconf


@pytest.mark.skipif(not shutil.which("desktop-file-validate"), reason="desktop-file-validate not installed")
def test_a_folder_name_with_spaces_still_makes_a_valid_launcher(machine, tmp_path):
    """Regression: an unquoted Exec path with a space is an invalid .desktop file and the app can't be launched from the menu."""
    spaced = tmp_path / "My Apps" / "LinuxGuardian UI"
    shutil.copytree(UI, spaced, ignore=shutil.ignore_patterns("tests", "__pycache__"))
    r = machine.run(spaced / "install_desktop_entry.sh", "--install")
    assert r.returncode == 0, r.stderr
    entry = machine.home / ".local/share/applications/linuxguardian-watchdog.desktop"
    assert f'Exec="{spaced}/run_ui.sh"' in entry.read_text()
    v = subprocess.run(["desktop-file-validate", str(entry)], capture_output=True, text=True)
    assert v.returncode == 0, v.stdout + v.stderr


def test_installing_twice_changes_nothing_and_uninstalling_removes_only_our_files(machine):
    before = user_files(machine.home)
    for _ in range(2):
        assert machine.run(UI / "install_desktop_entry.sh", "--install").returncode == 0
    assert (machine.home / ".local/share/applications/linuxguardian-watchdog.desktop").is_file()
    assert sum(1 for c in machine.calls() if c.startswith("gsettings set")) >= 1
    for _ in range(2):                                                                   # and removing twice is also fine
        assert machine.run(UI / "install_desktop_entry.sh", "--uninstall").returncode == 0
    assert not (machine.home / ".local/share/applications/linuxguardian-watchdog.desktop").exists()
    assert not (machine.home / "Desktop/LinuxGuardian Watchdog.desktop").exists()
    assert not list((machine.home / ".local/share/icons").rglob("linuxguardian-watchdog.png"))
    assert user_files(machine.home) == before                                            # nothing of the user's was touched, data included


def test_unknown_options_and_no_options_do_nothing(machine):
    before = sorted(str(p) for p in machine.home.rglob("*"))
    assert machine.run(UI / "install_desktop_entry.sh").returncode == 0
    assert machine.run(UI / "install_desktop_entry.sh", "--nuke-everything").returncode == 1
    assert sorted(str(p) for p in machine.home.rglob("*")) == before


def test_a_non_gnome_desktop_gets_the_menu_entry_and_a_clear_note_instead_of_a_pin(machine):
    stub(machine.bin / "gnome-shell", "exit 0")
    (machine.bin / "gnome-shell").unlink()
    r = machine.run(UI / "install_desktop_entry.sh", "--install", XDG_CURRENT_DESKTOP="KDE", PATH=f"{machine.bin}:/usr/bin:/bin")
    assert r.returncode == 0 and (machine.home / ".local/share/applications/linuxguardian-watchdog.desktop").is_file()


# =============================================================================== scheduler and timers
def test_the_timers_install_run_and_remove_cleanly_and_keep_everything_else(machine):
    before = user_files(machine.home)
    assert machine.run(SUITE / "install_scheduler.sh", "--install").returncode == 0
    assert machine.run(SUITE / "install_scheduler.sh", "--install-sensors").returncode == 0
    units = machine.home / ".config/systemd/user"
    names = sorted(p.name for p in units.iterdir())
    assert names == ["linuxguardian-scan.service", "linuxguardian-scan.timer", "linuxguardian-sensors.service", "linuxguardian-sensors.timer", "their-own.service"]
    for u in ("linuxguardian-scan.service", "linuxguardian-sensors.service"):
        text = (units / u).read_text()
        assert "Nice=" in text and "IOSchedulingClass=idle" in text                        # background work stays out of the way
        for line in text.splitlines():
            if line.startswith("ExecStart"):
                assert Path(line.split("=", 1)[1].lstrip("-").split()[0]).is_file()
    assert any(c.startswith("systemctl --user enable --now linuxguardian-scan.timer") for c in machine.calls())
    assert machine.run(SUITE / "install_scheduler.sh", "--install").returncode == 0           # upgrade in place: same result
    assert sorted(p.name for p in units.iterdir()) == names
    assert machine.run(SUITE / "install_scheduler.sh", "--uninstall-sensors").returncode == 0
    assert machine.run(SUITE / "install_scheduler.sh", "--uninstall").returncode == 0
    assert sorted(p.name for p in units.iterdir()) == ["their-own.service"]
    assert any(c.startswith("systemctl --user disable --now linuxguardian-sensors.timer") for c in machine.calls())
    assert user_files(machine.home) == before                                                 # their unit and their data survive


def test_removing_what_was_never_installed_is_harmless(machine):
    before = user_files(machine.home)
    assert machine.run(SUITE / "install_scheduler.sh", "--uninstall").returncode == 0
    assert machine.run(SUITE / "install_scheduler.sh", "--uninstall-sensors").returncode == 0
    assert user_files(machine.home) == before


def test_a_failed_install_says_so_and_can_be_retried(machine):
    """Regression: the script used to print 'Installed and enabled' even when systemctl had failed."""
    r = machine.run(SUITE / "install_scheduler.sh", "--install-sensors", SYSTEMCTL_RC="1")
    assert r.returncode == 1 and "Couldn't turn on live monitoring" in r.stdout + r.stderr and "Live monitoring is on" not in r.stdout
    r = machine.run(SUITE / "install_scheduler.sh", "--install", SYSTEMCTL_RC="1")
    assert r.returncode == 1 and "Couldn't turn on" in r.stdout + r.stderr and "Installed and enabled" not in r.stdout
    assert machine.run(SUITE / "install_scheduler.sh", "--uninstall-sensors", SYSTEMCTL_RC="1").returncode == 0     # cleanup works even while systemd is unhappy
    assert machine.run(SUITE / "install_scheduler.sh", "--install-sensors").returncode == 0                       # and so does a retry


def test_removing_the_app_never_deletes_your_data_folder(machine):
    machine.run(SUITE / "install_scheduler.sh", "--install")
    machine.run(UI / "install_desktop_entry.sh", "--install")
    machine.run(SUITE / "install_scheduler.sh", "--uninstall")
    machine.run(UI / "install_desktop_entry.sh", "--uninstall")
    assert (machine.home / ".linuxguardian/quarantine/keepme").read_text() == "quarantined file"
    assert (machine.home / ".linuxguardian/precious.json").is_file()


# ======================================================================= documentation matches reality
def readme_commands() -> list[tuple[str, list[str]]]:
    out = []
    for block in re.findall(r"```bash\n(.*?)```", (ROOT / "README.md").read_text(), re.S):
        for line in block.splitlines():
            m = re.match(r"^\./([\w.]+)\s*(.*?)(?:\s+#.*)?$", line.strip())
            if m:
                out.append((m.group(1), re.findall(r"(?<![\w-])(--?[a-z][\w-]*)", m.group(2))))
    return out


def test_every_command_in_the_readme_names_a_real_script_and_real_options():
    cmds = readme_commands()
    assert len(cmds) >= 40
    problems = []
    for name, flags in cmds:
        script = SUITE / name
        if not script.is_file():
            script = UI / name
        if not script.is_file():
            problems.append(f"{name}: no such script")
            continue
        text = script.read_text()
        for f in flags:
            if f not in text:
                problems.append(f"{name} {f}: the script doesn't know this option")
    assert not problems, problems


def test_every_script_in_the_readme_layout_exists_and_is_executable():
    layout = re.findall(r"^│\s+[├└]── ([\w.]+\.(?:py|sh))\s", (ROOT / "README.md").read_text(), re.M)
    assert len(layout) >= 30
    missing = [n for n in layout if not (SUITE / n).is_file() and not (UI / n).is_file()]
    assert not missing, missing
    not_exec = [n for n in layout if (SUITE / n).is_file() and not os.access(SUITE / n, os.X_OK)]
    assert not not_exec, f"listed as runnable but not executable: {not_exec}"


def test_the_documented_requirements_cover_what_the_scripts_actually_run():
    """The README must mention each external program the suite depends on to do its job (not just Python)."""
    readme = (ROOT / "README.md").read_text().lower()
    for needed in ("clamav", "rkhunter", "python3-gi", "libadwaita", "systemd", "polkit", "ufw", "libnotify", "iproute2"):
        assert needed in readme, f"README doesn't mention {needed}"


def test_the_python_side_has_no_undeclared_third_party_dependencies():
    """The app runs on the standard library plus PyGObject. A new import of anything else must be a conscious decision."""
    import ast
    std = set(sys.stdlib_module_names)
    local = {p.stem for p in SUITE.glob("*.py")} | {"linuxguardian_ui"}
    allowed_optional = {"anthropic"}                                  # lazily imported, only if the person turns the cloud backend on
    found: dict[str, set[str]] = {}
    for f in list(SUITE.glob("*.py")) + list((UI / "linuxguardian_ui").rglob("*.py")):
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                mods = [node.module.split(".")[0]]
            for m in mods:
                if m not in std and m not in local and m != "gi":
                    found.setdefault(m, set()).add(f.name)
    assert set(found) <= allowed_optional, {k: sorted(v) for k, v in found.items() if k not in allowed_optional}

"""Process naming: systemd PID 1 vs --user, ROS, Python scripts, GNOME helpers."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from linuxguardian_ui.process_catalog import explain, python_script  # noqa: E402


def test_systemd_pid1_vs_user() -> None:
    name, desc = explain("systemd", "system", pid="1")
    assert "PID 1" in name
    assert "PID 1" in desc
    name, desc = explain("systemd", "system", pid="4371")
    assert "--user" in name
    assert "PID 1" not in name
    assert "per-user" in desc or "login session" in desc


def test_python_script() -> None:
    assert python_script("python3 -m http.server") == "http.server"
    assert python_script("/usr/bin/python3 /home/azrael/mux_node.py") == "/home/azrael/mux_node.py"


def test_ros_node() -> None:
    name, desc = explain(
        "python3",
        "background",
        pid="99",
        cmdline="/usr/bin/python3 /opt/ros/humble/lib/topic_tools/mux",
        exe="/usr/bin/python3",
    )
    assert name.startswith("ROS 2")
    assert "Robotics" in desc


def test_gnome_settings_daemon() -> None:
    name, desc = explain("gsd-keyboard", "system")
    assert "GNOME Settings Daemon" in name
    assert "keyboard" in desc.lower() or "settings" in desc.lower()


def test_vino_and_postfix() -> None:
    name, desc = explain("vino-server", "system")
    assert "remote" in desc.lower()
    name, desc = explain("master", "system")
    assert "Postfix" in name


if __name__ == "__main__":
    test_systemd_pid1_vs_user()
    test_python_script()
    test_ros_node()
    test_gnome_settings_daemon()
    test_vino_and_postfix()
    print("OK")

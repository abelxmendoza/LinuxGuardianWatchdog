"""ROS firewall helper: narrow, validated, and never a way to open the machine to everyone."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import ros_firewall as rf  # noqa: E402


@pytest.mark.parametrize("domain,expected", [(0, "7400:7649"), (1, "7650:7899"), (42, "17900:18149"), (101, "32650:32899"), (232, "65400:65535")])
def test_dds_port_range_per_domain(domain, expected):
    assert rf.dds_range(domain) == expected


@pytest.mark.parametrize("bad", [-1, 233, 1000])
def test_impossible_domains_are_rejected(bad):
    with pytest.raises(ValueError):
        rf.dds_range(bad)


def test_the_range_never_exceeds_the_valid_port_space():
    for d in range(rf.MAX_DOMAIN + 1):
        lo, hi = (int(x) for x in rf.dds_range(d).split(":"))
        assert 0 < lo < hi <= 65535


@pytest.mark.parametrize("peer,normalized", [("192.168.1.50", "192.168.1.50"), (" 10.1.2.3 ", "10.1.2.3"), ("192.168.1.0/24", "192.168.1.0/24"),
                                              ("192.168.1.77/24", "192.168.1.0/24"), ("fd00::5", "fd00::5"), ("10.0.0.0/16", "10.0.0.0/16")])
def test_valid_peers(peer, normalized):
    assert rf.parse_peer(peer) == normalized


@pytest.mark.parametrize("bad", ["", "any", "Anywhere", "*", "0.0.0.0/0", "::/0", "10.0.0.0/8", "172.16.0.0/12", "0.0.0.0", "127.0.0.1",
                                 "224.0.0.1", "not-an-ip", "1.2.3.4; reboot", "1.2.3.4 any", "$(reboot)", "-1.2.3.4"])
def test_dangerous_or_nonsense_peers_are_refused(bad):
    with pytest.raises(ValueError):
        rf.parse_peer(bad)


def test_rules_are_exactly_the_domain_range_plus_chosen_presets():
    rs = rf.rules("192.168.1.50", 42, ["mavlink"])
    assert [(r["name"], r["proto"], r["ports"], r["peer"]) for r in rs] == [
        ("dds", "udp", "17900:18149", "192.168.1.50"), ("mavlink", "udp", "14540,14550", "192.168.1.50")]
    assert all("from 192.168.1.50" in r["command"] and "anywhere" not in r["command"].lower() for r in rs)


def test_unknown_presets_are_refused():
    with pytest.raises(ValueError):
        rf.rules("192.168.1.50", 0, ["ssh; reboot"])


def test_plan_promises_only_what_it_does():
    p = rf.plan("192.168.1.50", 0, [])
    assert "ONLY 192.168.1.50" in p["effect"] and "default policy stays deny" in p["effect"]
    assert "igmp" in p["notes"][0].lower()


def test_every_preset_is_shaped_so_the_root_script_accepts_it():
    import re
    for name, (proto, ports, _why) in rf.PRESETS.items():
        assert proto in ("udp", "tcp") and re.fullmatch(r"[0-9]+([:,][0-9]+)*", ports), name


# --------------------------------------------------------------------- detection
@pytest.fixture()
def box(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_ROS_HOME", str(tmp_path))
    monkeypatch.setenv("LG_ROS_OPT", str(tmp_path / "opt"))
    for k in ("ROS_DOMAIN_ID", "ROS_LOCALHOST_ONLY", "RMW_IMPLEMENTATION"):
        monkeypatch.delenv(k, raising=False)
    return tmp_path


def test_detect_reads_shell_start_up_files(box):
    (box / "opt" / "humble").mkdir(parents=True)
    (box / ".bashrc").write_text("export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp\nexport ROS_DOMAIN_ID=42   # lab\n# export ROS_DOMAIN_ID=7\n")
    d = rf.detect()
    assert d["domains"] == [42] and d["distros"] == ["humble"] and d["rmw"] == ["rmw_cyclonedds_cpp"] and d["ros_present"]


def test_detect_reports_every_declared_domain_when_the_file_is_conditional(box):
    (box / ".bashrc").write_text("if x; then\n  export ROS_DOMAIN_ID=42\nelse\n  export ROS_DOMAIN_ID=7\nfi\n")
    assert rf.detect()["domains"] == [42, 7]


def test_detect_defaults_to_domain_zero_and_says_it_was_not_declared(box):
    d = rf.detect()
    assert d["domains"] == [0] and not d["domain_declared"] and not d["ros_present"]


def test_localhost_only_means_no_rules_are_needed(box, monkeypatch):
    monkeypatch.setenv("ROS_LOCALHOST_ONLY", "1")
    d = rf.detect()
    assert d["localhost_only"] and "no firewall rules are needed" in d["note"]


def test_garbage_domain_values_are_ignored(box):
    (box / ".bashrc").write_text("export ROS_DOMAIN_ID=abc\nexport ROS_DOMAIN_ID=9999\n")
    assert rf.detect()["domains"] == [0]


def test_exposure_recognizes_the_users_own_ros_domain(box, monkeypatch):
    import exposure_inventory as ex

    (box / ".bashrc").write_text("export ROS_DOMAIN_ID=42\n")
    monkeypatch.setattr(ex, "_DDS_RANGES", None)
    assert ex.classify_port("udp", 17905)[0] == "ROS 2 / DDS discovery"      # domain 42 range
    assert ex.classify_port("udp", 7410)[0] == "ROS 2 / DDS discovery"       # domain 0 still recognised
    assert ex.classify_port("udp", 19000)[0] == "Unknown service"            # not ROS: stays unknown
    monkeypatch.setattr(ex, "_DDS_RANGES", None)

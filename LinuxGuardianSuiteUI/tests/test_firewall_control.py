"""Firewall control: status in plain language, rule parsing and fingerprints, rule plans, the block log."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SUITE = Path(__file__).resolve().parents[2] / "LinuxGuardianSuite"
sys.path.insert(0, str(SUITE))

import firewall_control as fc  # noqa: E402

# Shape of real `ufw status numbered` output (ufw 0.36).
NUMBERED = """\
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     LIMIT IN    192.168.1.0/24             # LinuxGuardian: home ssh
[ 2] 7400:7649/udp              ALLOW IN    192.168.1.50               # LinuxGuardian ROS dds
[ 3] 80/tcp                     ALLOW IN    Anywhere
[ 4] 445                        DENY IN     10.0.0.9
[ 5] 80/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 6] 25                         REJECT OUT  Anywhere                   (out)
"""

UFW_LOG = """\
Oct 13 10:48:01 host kernel: [  553.5] [UFW BLOCK] IN=wlp1 OUT= MAC= SRC=192.168.1.224 DST=239.255.0.7 LEN=114 PROTO=UDP SPT=10318 DPT=10318 LEN=94
Oct 13 10:48:21 host kernel: [  573.1] [UFW BLOCK] IN=wlp1 OUT= MAC= SRC=45.33.32.156 DST=192.168.1.10 LEN=60 PROTO=TCP SPT=40000 DPT=22 WINDOW=1024 SYN
Oct 13 10:48:22 host kernel: [  574.1] [UFW BLOCK] IN=wlp1 OUT= MAC= SRC=45.33.32.156 DST=192.168.1.10 LEN=60 PROTO=TCP SPT=40001 DPT=22 WINDOW=1024 SYN
Oct 13 10:48:30 host kernel: [  580.0] [UFW AUDIT] IN=wlp1 OUT= MAC= SRC=45.33.32.156 DST=192.168.1.10 PROTO=TCP SPT=1 DPT=22
Oct 13 10:48:40 host kernel: [  590.0] [UFW BLOCK] IN= OUT=wlp1 SRC=192.168.1.10 DST=198.51.100.1 LEN=60 PROTO=TCP SPT=5000 DPT=25
Oct 13 10:48:41 host kernel: [  591.0] [UFW BLOCK] IN=wlp1 OUT= MAC= SRC=fe80::1 DST=ff02::1 LEN=60 PROTO=ICMPv6 TYPE=134
something unrelated
"""


@pytest.fixture
def ufw_files(tmp_path, monkeypatch):
    conf, default, log, bin_ = tmp_path / "ufw.conf", tmp_path / "default", tmp_path / "ufw.log", tmp_path / "bin"
    bin_.mkdir()
    conf.write_text("# comment\nENABLED=yes\nLOGLEVEL=low\n")
    default.write_text('IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\nDEFAULT_FORWARD_POLICY="DROP"\n')
    log.write_text(UFW_LOG)
    (bin_ / "systemctl").write_text('#!/bin/sh\necho "${STUB_UFW_STATE:-active}"\n[ "${STUB_UFW_STATE:-active}" = active ]\n')
    (bin_ / "journalctl").write_text('#!/bin/sh\necho "Starting Uncomplicated firewall..."\necho "ip6tables-restore: line 4 failed"\n'
                                     'echo "ufw.service: Main process exited, code=exited, status=1/FAILURE"\n')
    (bin_ / "ufw").write_text("#!/bin/sh\nexit 0\n")
    for f in bin_.iterdir():
        f.chmod(0o755)
    monkeypatch.setenv("LG_UFW_CONF", str(conf))
    monkeypatch.setenv("LG_UFW_DEFAULT", str(default))
    monkeypatch.setenv("LG_UFW_LOG", str(log))
    monkeypatch.setenv("PATH", f"{bin_}:/usr/bin:/bin")
    return {"conf": conf, "default": default, "log": log}


# ---------------------------------------------------------------- status
def test_a_healthy_firewall_reads_as_on_with_its_defaults(ufw_files):
    st = fc.status("ufw")
    assert st["level"] == "ok" and st["headline"] == "Firewall is ON."
    assert st["policies"] == {"incoming": "deny", "outgoing": "allow", "routed": "deny"}
    assert st["logging"] == "low" and st["ipv6"] is True and st["service"] == "active"


def test_switched_off_is_critical(ufw_files):
    ufw_files["conf"].write_text("ENABLED=no\n")
    st = fc.status("none")
    assert st["level"] == "critical" and "OFF" in st["headline"]


def test_a_service_that_failed_to_start_names_the_real_reason(ufw_files, monkeypatch):
    monkeypatch.setenv("STUB_UFW_STATE", "failed")
    st = fc.status("unknown")
    assert st["level"] == "warning" and "failed to start" in st["headline"]
    assert st["failure"] == "ip6tables-restore: line 4 failed"          # not systemd's own "Main process exited" line
    assert "ip6tables-restore" in st["advice"]


def test_enabled_but_not_running_is_a_warning(ufw_files, monkeypatch):
    monkeypatch.setenv("STUB_UFW_STATE", "inactive")
    st = fc.status("unknown")
    assert st["level"] == "warning" and "isn't running" in st["headline"]


def test_default_allow_incoming_is_critical(ufw_files):
    ufw_files["default"].write_text('DEFAULT_INPUT_POLICY="ACCEPT"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n')
    st = fc.status("ufw")
    assert st["level"] == "critical" and st["policies"]["incoming"] == "allow"


def test_another_firewall_in_charge_is_reported_not_fought(ufw_files):
    st = fc.status("firewalld")
    assert st["level"] == "info" and "firewalld" in st["headline"] and "firewall-config" in st["advice"]


def test_no_ufw_at_all(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_UFW_CONF", str(tmp_path / "missing"))
    monkeypatch.setenv("LG_UFW_DEFAULT", str(tmp_path / "missing2"))
    monkeypatch.setenv("PATH", str(tmp_path))
    st = fc.status("none")
    assert st["installed"] is False and st["level"] == "critical" and "apt install ufw" in st["advice"]


# ---------------------------------------------------------------- rules
def test_numbered_rules_are_parsed_with_direction_v6_and_comments():
    parsed = fc.parse_numbered(NUMBERED)
    assert parsed["active"] is True
    rules = parsed["rules"]
    assert [r["num"] for r in rules] == [1, 2, 3, 4, 5, 6]
    assert rules[0]["action"] == "limit" and rules[0]["from"] == "192.168.1.0/24"
    assert rules[0]["comment"] == "LinuxGuardian: home ssh" and rules[0]["ours"] is True
    assert rules[2]["ours"] is False and rules[2]["from"] == "Anywhere"
    assert rules[4]["v6"] is True and rules[4]["to"] == "80/tcp"
    assert rules[5]["direction"] == "out" and rules[5]["action"] == "reject"


def test_an_inactive_firewall_has_no_rules():
    assert fc.parse_numbered("Status: inactive\n") == {"active": False, "rules": []}


def test_fingerprint_matches_what_the_root_script_computes():
    line = fc.parse_numbered(NUMBERED)["rules"][2]["line"]
    shell = subprocess.run(["sh", "-c", 'printf "%s" "$1" | sed "s/[[:space:]]*\\$//" | sha256sum | cut -c1-64', "sh", line + "   "],
                           capture_output=True, text=True, check=True).stdout.strip()
    assert shell == fc.fingerprint(line) == fc.fingerprint(line + "   ")


def test_rules_are_described_in_plain_words():
    rules = fc.parse_numbered(NUMBERED)["rules"]
    assert fc.describe_rule(rules[2]) == "Allows anyone reaching 80/tcp"
    assert fc.describe_rule(rules[3]) == "Blocks 10.0.0.9 reaching 445"
    assert "over IPv6" in fc.describe_rule(rules[4])
    assert fc.describe_rule(rules[5]).startswith("Refuses this laptop connecting out")


# ---------------------------------------------------------------- planning a rule
def test_a_narrow_rule_is_planned_exactly():
    p = fc.plan_add("allow", "8080", "tcp", "192.168.1.50", "dev server")
    assert p["words"] == ["allow", "proto", "tcp", "from", "192.168.1.50", "to", "any", "port", "8080", "comment", "LinuxGuardian: dev server"]
    assert p["command"] == "sudo ufw allow proto tcp from 192.168.1.50 to any port 8080 comment 'LinuxGuardian: dev server'"
    assert p["warnings"] == []


def test_open_to_anyone_and_remote_login_ports_are_warned_about():
    p = fc.plan_add("allow", "22", "tcp", "")
    assert p["from"] == "any" and len(p["warnings"]) == 2 and "anyone" in p["effect"]
    assert fc.plan_add("limit", "22", "tcp", "192.168.1.0/24")["warnings"] == []


@pytest.mark.parametrize("port,proto,expected", [("6000:6010", "udp", "6000:6010"), ("53", "any", "53"), ("443", "tcp", "443"), ("7:7", "tcp", "7")])
def test_ports_and_ranges(port, proto, expected):
    assert fc.plan_add("deny", port, proto)["ports"] == expected


@pytest.mark.parametrize("kwargs,msg", [
    ({"action": "open", "port": "22"}, "Unknown action"),
    ({"action": "allow", "port": "22", "proto": "sctp"}, "Unknown protocol"),
    ({"action": "allow", "port": "0"}, "1 to 65535"),
    ({"action": "allow", "port": "70000"}, "1 to 65535"),
    ({"action": "allow", "port": "10:5", "proto": "tcp"}, "low end first"),
    ({"action": "allow", "port": "22; reboot"}, "isn't a port"),
    ({"action": "allow", "port": "-1"}, "isn't a port"),
    ({"action": "allow", "port": "6000:6010", "proto": "any"}, "needs a protocol"),
    ({"action": "limit", "port": "53", "proto": "udp"}, "only works for TCP"),
    ({"action": "allow", "port": "22", "source": "evil.example.com"}, "isn't an IP"),
    ({"action": "allow", "port": "22", "source": "$(reboot)"}, "isn't an IP"),
    ({"action": "allow", "port": "22", "source": "224.0.0.1"}, "multicast"),
    ({"action": "allow", "port": "22", "label": "x'; reboot"}, "label"),
    ({"action": "allow", "port": "22", "label": "a" * 41}, "label"),
])
def test_bad_requests_are_refused_with_a_reason(kwargs, msg):
    with pytest.raises(ValueError, match=msg):
        fc.plan_add(kwargs["action"], kwargs["port"], kwargs.get("proto", "tcp"), kwargs.get("source", ""), kwargs.get("label", ""))


def test_any_and_slash_zero_both_mean_anyone():
    assert fc.plan_add("deny", "23", "tcp", "0.0.0.0/0")["from"] == "any"
    assert fc.plan_add("deny", "23", "tcp", "Anywhere")["from"] == "any"
    assert fc.plan_add("deny", "23", "tcp", "10.1.2.3/8")["from"] == "10.0.0.0/8"


# ---------------------------------------------------------------- block log
def test_recent_blocks_are_counted_by_source_and_port(ufw_files):
    b = fc.recent_blocks()
    assert b["readable"] and b["total"] == 5 and b["inbound"] == 4 and b["outbound"] == 1      # AUDIT lines are not blocks
    assert b["top_sources"][0] == {"addr": "45.33.32.156", "count": 2, "kind": "internet"}
    assert {"addr": "192.168.1.224", "count": 1, "kind": "local network"} in b["top_sources"]
    assert b["top_ports"][0] == {"port": "tcp/22", "count": 2}
    assert b["first"] == "Oct 13 10:48:01" and b["last"] == "Oct 13 10:48:41"


def test_an_unreadable_or_missing_log_says_why(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_UFW_LOG", str(tmp_path / "nope.log"))
    assert fc.recent_blocks()["readable"] is False
    locked = tmp_path / "locked.log"
    locked.write_text(UFW_LOG)
    locked.chmod(0)
    monkeypatch.setenv("LG_UFW_LOG", str(locked))
    if os.access(locked, os.R_OK):                                       # running as root
        pytest.skip("root can read anything")
    assert "adm" in fc.recent_blocks()["reason"]


# ---------------------------------------------------------------- CLI
def test_cli_status_blocks_plan_and_parse(ufw_files):
    def run(*args, stdin=None):
        return subprocess.run([sys.executable, str(SUITE / "firewall_control.py"), *args], input=stdin, capture_output=True, text=True)
    assert json.loads(run("--status", "--kind", "ufw", "--json").stdout)["level"] == "ok"
    assert json.loads(run("--blocks", "--json").stdout)["total"] == 5
    r = run("--plan-add", "--action", "allow", "--port", "22", "--from", "192.168.1.0/24")
    assert r.returncode == 0 and "sudo ufw allow proto tcp from 192.168.1.0/24" in r.stdout
    r = run("--plan-add", "--action", "allow", "--port", "nope")
    assert r.returncode == 2 and "isn't a port" in r.stderr
    assert len(json.loads(run("--parse-rules", "--json", stdin=NUMBERED).stdout)["rules"]) == 6

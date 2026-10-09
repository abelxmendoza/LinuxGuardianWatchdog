"""Network exposure detection: parsing, scope, severity, firewall inference, de-duplicated events."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "LinuxGuardianSuite"))

import exposure_inventory as exp  # noqa: E402
import events  # noqa: E402

# Shapes taken from real `ss -H -tulnp` output on the target machine.
SS_SAMPLE = """\
udp   UNCONN 0      0            0.0.0.0:41641      0.0.0.0:*
udp   UNCONN 0      0            0.0.0.0:7400       0.0.0.0:*
udp   UNCONN 0      0            0.0.0.0:7400       0.0.0.0:*
udp   UNCONN 0      0       127.0.0.53%lo:53        0.0.0.0:*
udp   UNCONN 0      0               [::]:41641         [::]:*
tcp   LISTEN 0      5            0.0.0.0:5900       0.0.0.0:*    users:(("vino-server",pid=5517,fd=12))
tcp   LISTEN 0      5               [::]:5900          [::]:*    users:(("vino-server",pid=5517,fd=11))
tcp   LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*
tcp   LISTEN 0      100        127.0.0.1:25        0.0.0.0:*
tcp   LISTEN 0      50           0.0.0.0:8080       0.0.0.0:*    users:(("Isolated Web Co",pid=99,fd=5),("helper",pid=100,fd=5))
tcp   ESTAB  0      0        10.0.0.5:5900      10.0.0.9:50000
udp   ESTAB  0      0        10.0.0.5:5353      10.0.0.9:5353
"""

IP_JSON = json.dumps(
    [
        {"ifname": "lo", "operstate": "UNKNOWN", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
        {"ifname": "wlp1", "operstate": "UP", "addr_info": [
            {"family": "inet", "local": "10.200.4.228", "prefixlen": 20},
            {"family": "inet6", "local": "fe80::3475:c013:6ea2:9cc4", "prefixlen": 64}]},
        {"ifname": "tailscale0", "operstate": "UNKNOWN", "addr_info": [{"family": "inet", "local": "100.101.2.3", "prefixlen": 32}]},
        {"ifname": "docker0", "operstate": "DOWN", "addr_info": [{"family": "inet", "local": "172.17.0.1", "prefixlen": 16}]},
        {"ifname": "eth9", "operstate": "UP", "addr_info": [{"family": "inet", "local": "93.184.216.34", "prefixlen": 24}]},
    ]
)

FW_OFF = {"state": "inactive", "kind": "ufw", "coverage": "none", "rules_readable": False, "note": "off"}
FW_DENY = {"state": "active", "kind": "ufw", "coverage": "default_deny", "rules_readable": False, "note": "deny"}
FW_ALLOW = {"state": "active", "kind": "ufw", "coverage": "permissive", "rules_readable": False, "note": "allow"}
FW_UNKNOWN = {"state": "active", "kind": "firewalld", "coverage": "unknown", "rules_readable": False, "note": "?"}
FW_NONE = {"state": "none", "kind": "none", "coverage": "none", "rules_readable": False, "note": "none"}


# ---------------------------------------------------------------- addresses
@pytest.mark.parametrize(
    "text,expected",
    [
        ("0.0.0.0:5900", ("0.0.0.0", "", 5900)),
        ("[::]:5900", ("::", "", 5900)),
        ("127.0.0.53%lo:53", ("127.0.0.53", "lo", 53)),
        ("[fe80::1]%wlan0:546", ("fe80::1", "wlan0", 546)),
        ("[::1]:631", ("::1", "", 631)),
        ("*:5900", ("*", "", 5900)),
        ("10.0.0.5:*", ("10.0.0.5", "", None)),
    ],
)
def test_parse_address(text: str, expected: tuple) -> None:
    assert exp.parse_address(text) == expected


def test_scope_classification() -> None:
    assert exp.bind_scope("0.0.0.0") == "all"
    assert exp.bind_scope("::") == "all"
    assert exp.bind_scope("*") == "all"
    assert exp.bind_scope("127.0.0.1") == "loopback"
    assert exp.bind_scope("::1") == "loopback"
    assert exp.bind_scope("127.0.0.53") == "loopback"
    assert exp.bind_scope("10.200.4.228") == "interface"


# ------------------------------------------------------------------ ss text
def test_parse_ss_listeners_keeps_only_real_listeners() -> None:
    ls = exp.parse_ss_listeners(SS_SAMPLE)
    keys = [(l["proto"], l["host"], l["port"]) for l in ls]
    assert ("tcp", "0.0.0.0", 5900) in keys and ("tcp", "::", 5900) in keys
    assert ("udp", "127.0.0.53", 53) in keys
    # an established TCP connection and a connected UDP socket are not listeners
    assert not any(l["port"] == 5900 and l["host"] == "10.0.0.5" for l in ls)
    assert not any(l["proto"] == "udp" and l["port"] == 5353 for l in ls)


def test_process_columns_survive_spaces_and_multiple_owners() -> None:
    ls = {l["port"]: l for l in exp.parse_ss_listeners(SS_SAMPLE) if l["proto"] == "tcp"}
    assert ls[5900]["procs"] == [("vino-server", 5517)]
    assert ls[8080]["procs"] == [("Isolated Web Co", 99), ("helper", 100)]
    assert ls[25]["procs"] == []  # not visible to a normal user


def test_parse_established() -> None:
    est = "0 0 10.0.0.5:5900 10.0.0.9:50000\n0 0 10.0.0.5:5900 10.0.0.9:50001\n0 0 10.0.0.5:5900 10.0.0.7:41000\n"
    assert exp.parse_established(est) == {5900: ["10.0.0.9", "10.0.0.7"]}  # peers de-duplicated, order kept


# --------------------------------------------------------------- interfaces
def test_interfaces_kinds_and_down_interfaces_skipped() -> None:
    ifs = exp.interfaces_from_ip_json(IP_JSON)
    by_iface = {i["iface"]: i for i in ifs if i["kind"] != "link_local"}
    assert "docker0" not in {i["iface"] for i in ifs}          # DOWN
    assert by_iface["lo"]["kind"] == "loopback"
    assert by_iface["wlp1"]["kind"] == "private" and by_iface["wlp1"]["cidr"] == "10.200.0.0/20"
    assert by_iface["tailscale0"]["kind"] == "vpn"              # CGNAT range
    assert by_iface["eth9"]["kind"] == "public"
    assert any(i["kind"] == "link_local" for i in ifs)


def test_interfaces_tolerate_garbage() -> None:
    assert exp.interfaces_from_ip_json("not json") == []
    assert exp.interfaces_from_ip_json('[{"ifname":"x","addr_info":[{"local":"bogus","prefixlen":8}]}]') == []


def test_reachable_networks() -> None:
    ifs = exp.interfaces_from_ip_json(IP_JSON)
    wide = exp.reachable_networks("all", "0.0.0.0", ifs)
    assert {n["iface"] for n in wide} == {"wlp1", "tailscale0", "eth9"}  # not lo, not link-local, not DOWN
    one = exp.reachable_networks("interface", "100.101.2.3", ifs)
    assert [n["iface"] for n in one] == ["tailscale0"]
    assert exp.reachable_networks("loopback", "127.0.0.1", ifs) == []


# -------------------------------------------------------------- port classes
def test_classify_port() -> None:
    assert exp.classify_port("tcp", 5900) == ("VNC remote desktop", exp.REMOTE_CONTROL)
    assert exp.classify_port("tcp", 5909)[1] == exp.REMOTE_CONTROL
    assert exp.classify_port("tcp", 5910)[1] == exp.UNKNOWN
    assert exp.classify_port("udp", 7400)[1] == exp.ROBOTICS
    assert exp.classify_port("udp", 7699)[1] == exp.ROBOTICS
    assert exp.classify_port("udp", 7700)[1] == exp.UNKNOWN
    assert exp.classify_port("udp", 5353)[1] == exp.DISCOVERY
    assert exp.classify_port("tcp", 5900)[1] != exp.classify_port("udp", 5900)[1]  # tcp-only range
    assert exp.classify_port("tcp", 54321) == ("Unknown service", exp.UNKNOWN)


# ----------------------------------------------------------------- severity
def nets(*kinds: str) -> list[dict]:
    return [{"iface": "x", "addr": "1.2.3.4", "cidr": "1.2.3.0/24", "kind": k} for k in kinds]


@pytest.mark.parametrize(
    "proto,cls,scope,networks,fw,expected",
    [
        # remote control reachable from the network
        ("tcp", exp.REMOTE_CONTROL, "all", nets("private"), FW_OFF, "critical"),
        ("tcp", exp.REMOTE_CONTROL, "all", nets("private"), FW_NONE, "critical"),
        ("tcp", exp.REMOTE_CONTROL, "all", nets("private"), FW_ALLOW, "critical"),
        ("tcp", exp.REMOTE_CONTROL, "all", nets("private"), FW_UNKNOWN, "critical"),  # can't verify -> no credit
        ("tcp", exp.REMOTE_CONTROL, "all", nets("private"), FW_DENY, "warning"),       # mitigated, unverifiable
        ("tcp", exp.REMOTE_CONTROL, "loopback", [], FW_OFF, "info"),                    # loopback is never a finding
        # databases / admin APIs
        ("tcp", exp.DATABASE, "all", nets("private"), FW_OFF, "critical"),
        ("tcp", exp.ADMIN, "all", nets("private"), FW_DENY, "warning"),
        # ordinary TCP services
        ("tcp", exp.WEB, "all", nets("private"), FW_OFF, "warning"),
        ("tcp", exp.WEB, "all", nets("private"), FW_DENY, "info"),
        ("tcp", exp.UNKNOWN, "all", nets("private"), FW_NONE, "warning"),
        ("tcp", exp.REMOTE_LOGIN, "all", nets("private"), FW_OFF, "warning"),
        # UDP chatter stays quiet unless it is a control interface
        ("udp", exp.ROBOTICS, "all", nets("private"), FW_OFF, "info"),
        ("udp", exp.DISCOVERY, "all", nets("private"), FW_OFF, "info"),
        ("udp", exp.UNKNOWN, "all", nets("private"), FW_OFF, "info"),
        ("udp", exp.ADMIN, "all", nets("private"), FW_OFF, "warning"),
        ("udp", exp.ADMIN, "all", nets("private"), FW_DENY, "info"),
        # reachable only over a VPN: one step down
        ("tcp", exp.DATABASE, "interface", nets("vpn"), FW_OFF, "warning"),
        ("tcp", exp.DATABASE, "interface", nets("vpn"), FW_DENY, "info"),
        ("tcp", exp.DATABASE, "interface", nets("vpn", "private"), FW_OFF, "critical"),  # mixed: not VPN-only
        ("tcp", exp.DATABASE, "all", nets("vpn"), FW_OFF, "critical"),                   # wildcard is not "VPN only"
    ],
)
def test_severity_matrix(proto, cls, scope, networks, fw, expected) -> None:
    assert exp.final_severity(proto, cls, scope, networks, fw) == expected


# ----------------------------------------------------------------- firewall
@pytest.fixture
def fw_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    conf = tmp_path / "ufw.conf"
    defaults = tmp_path / "ufw-default"
    monkeypatch.setenv("LG_UFW_CONF", str(conf))
    monkeypatch.setenv("LG_UFW_DEFAULTS", str(defaults))
    monkeypatch.setattr(exp.os, "access", lambda *a, **k: False)  # never depend on the host's /etc/ufw

    def configure(*, conf_text: str | None, default_text: str | None, active: set[str]) -> None:
        if conf_text is not None:
            conf.write_text(conf_text)
        if default_text is not None:
            defaults.write_text(default_text)
        monkeypatch.setattr(
            exp, "_run", lambda cmd, t: "active\n" if cmd[:2] == ["systemctl", "is-active"] and cmd[2] in active else "inactive\n"
        )

    return configure


@pytest.mark.parametrize(
    "policy,coverage",
    [("DROP", "default_deny"), ("REJECT", "default_deny"), ("ACCEPT", "permissive"), ("WEIRD", "unknown")],
)
def test_ufw_active_coverage_from_default_policy(fw_env, policy: str, coverage: str) -> None:
    fw_env(conf_text="ENABLED=yes\n", default_text=f'DEFAULT_INPUT_POLICY="{policy}"\n', active={"ufw"})
    fw = exp.firewall_status()
    assert (fw["state"], fw["kind"], fw["coverage"]) == ("active", "ufw", coverage)
    assert fw["rules_readable"] is False
    assert "root" in fw["note"]  # honest about what it can't see


def test_ufw_disabled_is_inactive_even_if_service_is_up(fw_env) -> None:
    fw_env(conf_text="ENABLED=no\n", default_text='DEFAULT_INPUT_POLICY="DROP"\n', active={"ufw"})
    assert exp.firewall_status()["state"] == "inactive"


def test_other_firewalls_and_none(fw_env) -> None:
    fw_env(conf_text="ENABLED=no\n", default_text=None, active={"firewalld"})
    assert exp.firewall_status()["kind"] == "firewalld" and exp.firewall_status()["coverage"] == "unknown"
    fw_env(conf_text="ENABLED=no\n", default_text=None, active={"nftables"})
    assert exp.firewall_status()["kind"] == "nftables"
    fw_env(conf_text="ENABLED=no\n", default_text=None, active=set())
    assert exp.firewall_status()["state"] == "inactive"  # ufw present but off
    fw_env(conf_text="ENABLED=yes\n", default_text=None, active=set())
    assert exp.firewall_status()["state"] == "none"       # enabled in config but not running


# ------------------------------------------------------------ build_services
def build(ss: str = SS_SAMPLE, fw: dict = FW_DENY, est: dict | None = None) -> dict[str, dict]:
    ifs = exp.interfaces_from_ip_json(IP_JSON)
    services = exp.build_services(exp.parse_ss_listeners(ss), est or {}, ifs, fw)
    return {s["id"]: s for s in services}


def test_dual_stack_and_duplicate_sockets_merge_into_one_finding() -> None:
    svc = build()
    vnc = svc["tcp:5900:vino-server"]
    assert {b["host"] for b in vnc["binds"]} == {"0.0.0.0", "::"}
    assert vnc["scope"] == "all" and vnc["pid"] == 5517
    assert sum(1 for s in svc.values() if s["port"] == 7400) == 1   # two sockets, one finding
    assert sum(1 for s in svc.values() if s["port"] == 41641) == 1  # v4 + v6


def test_findings_and_ordering() -> None:
    services = list(build().values())
    exp_sorted = exp.build_services(
        exp.parse_ss_listeners(SS_SAMPLE), {}, exp.interfaces_from_ip_json(IP_JSON), FW_DENY
    )
    assert exp_sorted[0]["id"] == "tcp:5900:vino-server"                      # worst first
    assert exp_sorted[0]["severity"] == "warning"                              # critical, lowered by default-deny
    loop = [s for s in services if s["scope"] == "loopback"]
    assert {s["port"] for s in loop} == {53, 25}
    assert all(s["severity"] == "info" for s in loop)
    # loopback findings sort after reachable ones of the same severity
    infos = [s for s in exp_sorted if s["severity"] == "info"]
    assert [s["scope"] == "loopback" for s in infos] == sorted(s["scope"] == "loopback" for s in infos)


def test_firewall_state_changes_the_verdict_for_the_same_listener() -> None:
    assert build(fw=FW_DENY)["tcp:5900:vino-server"]["severity"] == "warning"
    assert build(fw=FW_OFF)["tcp:5900:vino-server"]["severity"] == "critical"
    assert build(fw=FW_ALLOW)["tcp:5900:vino-server"]["severity"] == "critical"


def test_unknown_owner_is_labelled_not_guessed() -> None:
    dds = build()["udp:7400:unknown"]
    assert dds["owner_known"] is False and dds["process"] is None and dds["friendly"] is None
    assert any("can't be shown without root" in r for r in dds["reasons"])


def test_peers_attach_to_tcp_listeners_only() -> None:
    svc = build(est={5900: ["10.0.0.9"], 5353: ["10.0.0.9"]})
    assert svc["tcp:5900:vino-server"]["peers"] == ["10.0.0.9"]
    assert all(s["peers"] == [] for s in svc.values() if s["proto"] == "udp")


def test_reasons_are_quiet_for_routine_listeners_and_explicit_for_real_findings() -> None:
    svc = build()
    assert FW_DENY["note"] not in svc["udp:41641:unknown"]["reasons"]        # routine: no firewall boilerplate
    assert FW_DENY["note"] in svc["tcp:5900:vino-server"]["reasons"]          # a real finding: firewall context
    assert "Settings" in svc["tcp:5900:vino-server"]["advice"]               # vino-specific, manual advice


def test_public_address_is_called_out() -> None:
    vnc = build()["tcp:5900:vino-server"]
    assert any(n["kind"] == "public" for n in vnc["reachable_via"])
    assert any("internet" in r for r in vnc["reasons"])


def test_nothing_in_the_report_is_an_action() -> None:
    # Detection only: advice is prose, and no field is a command to run.
    for s in build().values():
        assert isinstance(s["advice"], str) and not s["advice"].lstrip().startswith(("sudo", "ufw", "kill"))


# ----------------------------------------------------------------- summary
def test_summary_line_is_parseable_and_has_no_spaces_in_values() -> None:
    ifs = exp.interfaces_from_ip_json(IP_JSON)
    services = exp.build_services(exp.parse_ss_listeners(SS_SAMPLE), {}, ifs, FW_DENY)
    meta = {
        "ss_ok": True, "firewall": FW_DENY, "listeners": len(services),
        "counts": {"critical": 0, "warning": 1, "info": 5, "loopback": 2},
    }
    kv = dict(part.split("=", 1) for part in exp.render_summary(meta, services).split(" "))
    assert kv["warning"] == "1" and kv["firewall"] == "ufw" and kv["coverage"] == "default_deny"
    assert kv["top"] == "vino-server:5900/tcp" and kv["ss_ok"] == "1"


def test_summary_top_is_dash_when_nothing_needs_attention() -> None:
    quiet = "udp   UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\n"
    ifs = exp.interfaces_from_ip_json(IP_JSON)
    services = exp.build_services(exp.parse_ss_listeners(quiet), {}, ifs, FW_DENY)
    meta = {"ss_ok": True, "firewall": FW_DENY, "listeners": 1,
            "counts": {"critical": 0, "warning": 0, "info": 1, "loopback": 0}}
    assert "top=-" in exp.render_summary(meta, services)


# ------------------------------------------------------------ recording
@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("LG_HOME", str(tmp_path))
    return tmp_path


def services_with(fw: dict) -> list[dict]:
    return list(build(fw=fw).values())


def test_record_writes_only_new_reachable_findings_and_stays_quiet_after(home: Path) -> None:
    first = exp.record_new_exposures(services_with(FW_DENY))
    assert len(first) == 1                       # the VNC warning; routine + loopback never recorded
    ev = json.loads(first[0].read_text())
    assert (ev["category"], ev["severity"], ev["event"], ev["status"]) == ("network", "warning", "exposed_service", "detected")
    assert (ev["process"], ev["port"], ev["protocol"], ev["pid"]) == ("vino-server", 5900, "tcp", 5517)
    assert exp.record_new_exposures(services_with(FW_DENY)) == []   # unchanged: silent


def test_record_notices_a_severity_change_and_a_reappearance(home: Path) -> None:
    exp.record_new_exposures(services_with(FW_DENY))                 # warning
    changed = exp.record_new_exposures(services_with(FW_OFF))        # firewall dropped
    # Two things move: VNC goes warning -> critical (a CHANGE), and the :8080 web
    # server goes info -> warning (newly worth knowing about). Both are correct.
    evs = {json.loads(p.read_text())["port"]: json.loads(p.read_text()) for p in changed}
    assert set(evs) == {5900, 8080}
    assert (evs[5900]["severity"], evs[5900]["event"], evs[5900]["status"]) == ("critical", "exposure_changed", "changed")
    assert (evs[8080]["severity"], evs[8080]["event"], evs[8080]["status"]) == ("warning", "exposed_service", "detected")

    assert exp.record_new_exposures([]) == []                        # it went away: no event, state cleared
    back = exp.record_new_exposures(services_with(FW_OFF))           # ...and came back: new again
    assert len(back) == 2 and {json.loads(p.read_text())["event"] for p in back} == {"exposed_service"}


def test_record_survives_a_corrupt_state_file(home: Path) -> None:
    state = home / "state" / "exposure.json"
    state.parent.mkdir(parents=True)
    state.write_text("{not json")
    assert len(exp.record_new_exposures(services_with(FW_DENY))) == 1
    assert json.loads(state.read_text()) == {"tcp:5900:vino-server": "warning"}


# ------------------------------------------------------------ events.py
def test_events_roundtrip_and_core_fields(home: Path) -> None:
    path = events.record_event("network", "critical", "exposed_service", "VNC is open", port=5900, process=None)
    data = json.loads(path.read_text())
    assert {"timestamp", "category", "severity", "message", "event", "status", "port"} <= data.keys()
    assert "process" not in data                      # None extras are dropped, not written as null
    assert events.read_events()[0]["message"] == "VNC is open"
    assert not list((home / "incidents").glob(".*.tmp"))   # atomic write leaves no temp file behind


def test_events_validate_input(home: Path) -> None:
    with pytest.raises(ValueError):
        events.record_event("network", "high", "x", "m")               # not our vocabulary
    with pytest.raises(ValueError):
        events.record_event("network", "info", "x", "m", status="done")
    with pytest.raises(ValueError):
        events.record_event("network", "info", "x", "m", timestamp="1970-01-01")  # can't override a core field
    with pytest.raises(ValueError):
        events.record_event("", "info", "x", "m")
    assert not (home / "incidents").exists() or not list((home / "incidents").glob("*.json"))


def test_events_reader_accepts_old_shell_records_and_skips_junk(home: Path) -> None:
    d = home / "incidents"
    d.mkdir(parents=True)
    # exactly what `lg_record_incident` in utils.sh writes
    (d / "20261007-100000-1-1.json").write_text(
        '{"timestamp":"2026-10-07T10:00:00-0700","category":"audit","severity":"warning","message":"old style"}\n'
    )
    (d / "20261007-110000-1-2.json").write_text("{broken")
    (d / "20261007-120000-1-3.json").write_text('["not","a","dict"]')
    (d / "20261007-130000-1-4.json").write_text('{"severity":"info"}')       # missing message
    new = events.record_event("network", "info", "x", "new style")
    got = events.read_events()
    assert [e["message"] for e in got] == ["new style", "old style"]          # newest first, junk skipped
    assert new.exists()


def test_events_reader_limit_and_missing_dir(home: Path) -> None:
    assert events.read_events() == []                                         # no dir yet
    for i in range(5):
        events.record_event("t", "info", "e", f"m{i}")
    assert len(events.read_events(limit=3)) == 3

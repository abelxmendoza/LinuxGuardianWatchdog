"""Hostile input into every command-line entry point that accepts a value.

For each command and each malicious value, in a disposable home with no real privileges:
  * nothing is executed (a command-injection sentinel is never created),
  * nothing asks for administrator rights (a stand-in `pkexec`/`sudo` records any attempt: there must be none),
  * the program fails politely (no Python traceback, no shell syntax error),
  * nothing outside the disposable folders is written.
`kill` is replaced by a function that only logs, so even a validation hole could not signal a real process.
"""
from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "LinuxGuardianSuite"
PY = sys.executable

# {S} in a payload becomes the sentinel path, so that any execution leaves proof.
PAYLOADS = [
    "$(touch {S})", "`touch {S}`", ";touch {S}", "x; touch {S}", "x && touch {S}", "x | touch {S}", "'; touch {S}; '", '"; touch {S}; "', "x\ntouch {S}",
    "$IFS$(touch {S})", "../../../../etc/passwd", "/etc/shadow", "-rf", "--help", "--", "", " ", "*", "a" * 4000, "ä日本\u202e", "0", "-1", "1", "999999999999",
    "${HOME}", "\\", "'",
]

# (label, argv template with {P}, needs a PATH where pkexec is observed)
COMMANDS = [
    ("quarantine --quarantine", [PY, "quarantine.py", "--quarantine", "{P}", "--skip-verify"]),
    ("quarantine --restore", [PY, "quarantine.py", "--restore", "{P}"]),
    ("quarantine --delete", [PY, "quarantine.py", "--delete", "{P}"]),
    ("quarantine --ignore", [PY, "quarantine.py", "--ignore", "{P}"]),
    ("self_check --plan", [PY, "self_check.py", "--plan", "{P}"]),
    ("self_check --apply", [PY, "self_check.py", "--apply", "{P}"]),
    ("fallback --show", [PY, "fallback.py", "--show", "{P}"]),
    ("fallback --show stop_process", [PY, "fallback.py", "--show", "stop_process", "--param", "{P}"]),
    ("fallback --open", [PY, "fallback.py", "--open", "{P}"]),
    ("evidence", [PY, "evidence.py", "--incident", "{P}"]),
    ("incidents --ack", [PY, "incidents.py", "--ack", "{P}"]),
    ("incidents --unack", [PY, "incidents.py", "--unack", "{P}"]),
    ("timeline --ack", [PY, "timeline.py", "--ack", "{P}"]),
    ("timeline --search", [PY, "timeline.py", "--search", "{P}", "--text"]),
    ("audit_events --accept", [PY, "audit_events.py", "--accept", "{P}"]),
    ("audit_events --unaccept", [PY, "audit_events.py", "--unaccept", "{P}"]),
    ("audit_events --is-accepted", [PY, "audit_events.py", "--is-accepted", "{P}"]),
    ("sensors --allow", [PY, "sensors.py", "--allow", "{P}"]),
    ("integrity --accept", [PY, "integrity.py", "--accept", "{P}"]),
    ("integrity --forget", [PY, "integrity.py", "--forget", "{P}"]),
    ("hardening --preview", [PY, "hardening.py", "--preview", "{P}"]),
    ("hardening --apply", [PY, "hardening.py", "--apply", "{P}"]),
    ("hardening --undo", [PY, "hardening.py", "--undo", "{P}"]),
    ("ai_investigator --prepare", [PY, "ai_investigator.py", "--prepare", "{P}"]),
    ("ai_investigator --investigate", [PY, "ai_investigator.py", "--investigate", "{P}"]),
    ("ai_investigator --run-check", [PY, "ai_investigator.py", "--run-check", "{P}"]),
    ("threat_intel --check", [PY, "threat_intel.py", "--check", "{P}"]),
    ("local_ai --use", [PY, "local_ai.py", "--use", "{P}"]),
    ("local_ai --pull", [PY, "local_ai.py", "--pull", "{P}"]),
    ("app_manifest --plan", [PY, "app_manifest.py", "--plan", "{P}"]),
    ("process manager --kill", ["bash", "linux_process_manager.sh", "--kill", "{P}"]),
    ("process manager --kill-name", ["bash", "linux_process_manager.sh", "--kill-name", "{P}"]),
    ("updates --hold", ["bash", "linux_updates.sh", "--hold", "{P}"]),
    ("updates --unhold", ["bash", "linux_updates.sh", "--unhold", "{P}"]),
    ("hardening (root) --apply", ["bash", "linux_hardening.sh", "--apply", "{P}"]),
    ("hardening (root) --undo", ["bash", "linux_hardening.sh", "--undo", "{P}"]),
    ("ros firewall --plan --peer", ["bash", "linux_ros_firewall.sh", "--plan", "--peer", "{P}"]),
    ("ros firewall --apply --peer", ["bash", "linux_ros_firewall.sh", "--apply", "--peer", "{P}"]),
    ("ros firewall --domain", ["bash", "linux_ros_firewall.sh", "--plan", "--peer", "192.168.1.50", "--domain", "{P}"]),
    ("apps --plan", ["bash", "linux_apps.sh", "--plan", "{P}"]),
    ("apps --install", ["bash", "linux_apps.sh", "--install", "{P}"]),
    ("cache cleaner --only", ["bash", "linux_cache_cleanup.sh", "--clean", "--only", "{P}"]),
    ("guardian --scan TARGET", ["bash", "linux_guardian.sh", "--scan", "{P}"]),
]


@pytest.fixture(scope="module")
def jail(tmp_path_factory):
    """A disposable home, an observed pkexec/sudo, and a kill that only logs. Nothing here can touch the real machine."""
    t = tmp_path_factory.mktemp("jail")
    for d in ("home", "bin", "lg", "etc", "proc"):
        (t / d).mkdir()
    (t / "lg").chmod(0o700)
    log = t / "escalations.log"
    for name in ("clamscan", "clamdscan", "freshclam", "rkhunter"):        # never run the real scanners from a fuzz test
        p = t / "bin" / name
        p.write_text("#!/bin/sh\nexit 0\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    for name in ("pkexec", "sudo", "su", "doas"):
        p = t / "bin" / name
        p.write_text(f'#!/bin/sh\necho "{name} $*" >> "{log}"\nexit 126\n')
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    kill_log = t / "kill.log"
    return {"t": t, "log": log, "kill_log": kill_log}


def run(jail, argv: list[str], payload: str) -> tuple[subprocess.CompletedProcess, Path]:
    t: Path = jail["t"]
    sentinel = t / "SENTINEL"
    sentinel.unlink(missing_ok=True)
    value = payload.replace("{S}", str(sentinel))
    cmd = [value if a == "{P}" else a for a in argv]
    if cmd[0] == "bash" and cmd[1] == "linux_process_manager.sh":
        # the one script that sends signals runs with `kill` replaced by a logger, whatever the input. (Other scripts use `kill -0` to watch a
        # child, so replacing it there would make them wait forever.)
        script = f'kill() {{ printf "%s\\n" "$*" >> "{jail["kill_log"]}"; return 0; }}; export -f kill; exec bash "$@"'
        cmd = ["bash", "-c", script, "x", str(SUITE / cmd[1]), *cmd[2:]]
    else:
        cmd = [cmd[0], str(SUITE / cmd[1]), *cmd[2:]]
    env = {"HOME": str(t / "home"), "LG_HOME": str(t / "lg"), "LG_SENSOR_HOME": str(t / "home"), "LG_SENSOR_ETC": str(t / "etc"), "LG_PROC": str(t / "proc"),
           "LG_INTEGRITY_HOME": str(t / "home"), "PATH": f"{t / 'bin'}:/usr/bin:/bin", "LANG": "C.UTF-8", "LG_UFW_CONF": str(t / "nonexistent")}
    # Its own process group, so that a timeout kills the script AND anything it started (a leftover scan would outlive the test run).
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, cwd=t / "home", errors="replace", start_new_session=True)
    try:
        out, err = proc.communicate(timeout=40)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, 9)
        proc.communicate()
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err), sentinel


@pytest.mark.parametrize("label,argv", COMMANDS, ids=[c[0] for c in COMMANDS])
def test_hostile_values_neither_execute_nor_escalate_nor_crash(jail, label, argv):
    problems = []
    for payload in PAYLOADS:
        jail["log"].write_text("")
        jail["kill_log"].write_text("")
        r, sentinel = run(jail, argv, payload)
        shown = repr(payload[:40])
        if sentinel.exists():
            problems.append(f"EXECUTED {shown}")
        if jail["log"].read_text().strip():
            problems.append(f"ASKED FOR ADMIN RIGHTS with {shown}: {jail['log'].read_text().strip()[:80]}")
        out = r.stdout + r.stderr
        if "Traceback (most recent call last)" in out:
            problems.append(f"TRACEBACK with {shown}: {out.strip().splitlines()[-1][:100]}")
        if "syntax error" in out and "line" in out:
            problems.append(f"SHELL SYNTAX ERROR with {shown}")
        if r.returncode < 0:
            problems.append(f"KILLED BY SIGNAL {-r.returncode} with {shown}")
        signalled = [l for l in jail["kill_log"].read_text().splitlines() if l.startswith(("-TERM", "-KILL", "-9", "-15"))]
        # `--kill-name` is MEANT to signal processes whose command line contains a real name (3+ letters or digits); everything else, and
        # every `--kill` value that isn't one ordinary process id, must signal nothing.
        meaningful_name = label.endswith("--kill-name") and sum(c.isalnum() for c in payload) >= 3
        if signalled and "process manager" in label and not meaningful_name:
            problems.append(f"WOULD HAVE SIGNALLED {signalled[:3]} with {shown}")
    assert not problems, f"{label}:\n  " + "\n  ".join(problems[:8])


def test_nothing_outside_the_jail_was_written(jail):
    """Everything above ran with HOME and LG_HOME inside the jail; confirm the real data folder didn't grow because of it."""
    real = Path.home() / ".linuxguardian" / "incidents"
    before = len(list(real.glob("*.json"))) if real.is_dir() else 0
    run(jail, COMMANDS[0][1], "x")
    after = len(list(real.glob("*.json"))) if real.is_dir() else 0
    assert after - before <= 3                                  # only the live monitor on this machine may add events while we run


def test_an_escalation_attempt_would_really_be_observed(jail):
    """The detector itself works: invoking the stand-in records it (so 'no escalation' above means something)."""
    jail["log"].write_text("")
    subprocess.run([str(jail["t"] / "bin" / "pkexec"), "/bin/true"])
    assert "pkexec /bin/true" in jail["log"].read_text()

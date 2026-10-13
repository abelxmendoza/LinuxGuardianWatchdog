# Release readiness: Phase 1.0 stabilization

Date of this verification: 2026-10-12. Scope: the code in this working tree on top of commit `24b1aea`. Nothing here claims LinuxGuardian
protects against malware or attacks. It is a monitor and a set of user-approved helpers; this document says only what was actually run.

## Verdict

**Class B: ready for limited daily use by its owner on the target laptop (Ubuntu 22.04, GNOME/X11).** It is not yet Class C or D.

Why not C yet (each is a concrete, checkable gap, not a feeling):

1. The GitHub Actions workflows have never run on GitHub. Locally they were validated as YAML and every command in them was run by hand.
2. Everything that needs real administrator rights (`apt`, `ufw`, `freshclam`, `rkhunter`, `pkexec` prompts) was tested against stand-in
   programs only. The fixed root scripts are covered, the real tools are not.
3. No long-running soak: the monitor has only been observed for hours, not weeks, and not under ROS 2 / PX4 / Gazebo / Docker load.
4. No test uses a real malware detection or a real attacker. Detection quality against real attacks is unmeasured.

Moving to C needs: one green CI run on GitHub, a hand run of the privileged flows on a disposable Ubuntu 22.04 machine, and about a week
of use on your own laptop with no false-alarm complaints. Class D (other people's machines) additionally needs packaging (a `.deb`), a
supported-distribution matrix and an independent review; none of that was attempted.

## What was run (all executed in this session on the target laptop, in throwaway data folders)

| Check | Result |
|---|---|
| `pytest` (unit, integration, end to end incl. real GTK window under display `:1`, regression, security-input fuzz, failure/recovery, packaging) | **1398 passed**, 0 failed, 0 skipped, 2 warnings, 195 s |
| Shell suites `tests/test_*.sh` (8 files: apps install, audit score, firewall detect, privileged scanner, hardening root, ROS firewall, scripts, updates) | **8 of 8 exit 0** |
| `ruff check .` (config `ruff.toml`) | clean |
| `bandit -ll` (medium and high severity; config `.bandit`, skips each justified in the file) | clean after four `B310` URL-open sites were annotated (all four are validated loopback URLs or one fixed https URL) |
| `shellcheck -S warning` on every suite and installer script | clean |
| `pip-audit -r requirements-dev.txt` | no known vulnerabilities (these are test tools only; the app itself uses the standard library plus the distribution's PyGObject) |
| Mutation checks on security-relevant guards (break the guard in a copy, confirm a test fails) | done by hand with a scratch harness on the guards added in this phase (for example the four packaging mutants were all caught); not exhaustive and not rerun as part of this final sweep |

Coverage (line, `pytest-cov`): **79 % overall** (14,173 statements). Backend modules are mostly 85 to 100 %. Weak spots, stated plainly:
`scan_watch.py` 0 %, `ai_dialogs.py` 10 %, `local_ai_window.py` 11 %, `dialogs.py` 11 %, `live_scan.py` 37 %, `apps.py` 43 %,
`updates.py` 58 %, `scan_store.py` 69 %, `scripts.py` 68 %. These are mostly GTK dialog code that needs a person clicking; coverage was not
chased for its own sake.

## Defects found and fixed in this phase

Severity is my own judgement: P0 = destroys data or runs attacker code with no user action; P1 = silently defeats a security function or
can hurt the user's machine; P2 = wrong or noisy behavior, limited impact; P3 = cosmetic or rough edge. Each has a regression test.

| Sev | Defect | Fix |
|---|---|---|
| P1 | `pgrep -f ""` style kill-by-name could match every process | PID and name validation, own-user only, critical names skipped, cap of `LG_KILL_MAX` |
| P1 | Config file was `source`d as shell code | Data-only parser with allow-list and ownership/permission checks |
| P1 | Sensor run crashed when the data folder was unwritable, so monitoring silently stopped | Write errors reported; run lock and atomic writes; self-check flags it |
| P1 | Quarantine "verification" could trust a scanner daemon that was not running | Daemon used only if `clamdscan --ping` succeeds, else `clamscan` |
| P2 | Integrity warnings were classified as findings, not incidents | Warning/critical integrity events are incidents |
| P2 | A new git hook in the app's own checkout was ignored | Treated as persistence (warning) |
| P2 | Two events in the same second could lose a desktop notification | Boundary-second announce memory |
| P2 | One binary or malformed event file crashed Timeline readers | Unknown severity or non-text message dropped on read |
| P2 | Shell helper could write invalid JSON for odd messages | Proper JSON escaping |
| P2 | Local-AI URL was not checked to be loopback | Validated for chat and for model pulls |
| P2 | Scheduler installer printed success when `systemctl` failed | Exit codes checked |
| P2 | Critical-name check never matched names at the start of a line | Names normalized |
| P3 | Desktop entry `Exec` path was not quoted | Quoted |
| P3 | Empty `--plan` / `--names` arguments raised tracebacks | Polite refusal |

Earlier in the same effort (reliability pass, commit `24b1aea`): risk acceptance, quiet development checkouts, alert classification.
Test-infrastructure bugs found on the way (a test that re-pointed itself at the real home folder, races on same-second events and reused
inode numbers, leftover fuzz processes) were fixed and are guarded by `test_hygiene.py`.

## Performance (measured, one machine, one run each unless stated)

Laptop: the target RTX 5070 machine, otherwise idle, real `/proc`, throwaway data folder, no desktop notifications sent.

| Measurement | Result |
|---|---|
| Sensors, first run (builds baselines) | 3.19 s wall, about 3.2 s CPU, 25 MB peak memory |
| Sensors, steady state (11 runs) | 0.17 to 0.19 s wall, about 0.17 s CPU, 24 MB peak memory. On the 5-minute timer that is roughly 0.06 % of one core |
| Data written by 12 sensor runs | 88 KB, 7 files |
| GUI start | import 0.09 s, window built 0.14 s |
| GUI idle (20 s window) | 0.03 s CPU, 4 threads, about 186 MB resident memory (GTK4 itself dominates) |
| Event store at 1,000 and 10,000 synthetic files | Timeline load 0.02 s and 0.18 s; incident build 0.02 s and 0.19 s; 200 newest events read in 0.03 s at 10,000 |

**Not measured:** a full guardian scan with ClamAV / rkhunter (needs the real tools and root), behavior while ROS 2 / PX4 / Gazebo /
Docker builds or large C++ compiles are running, large repositories under integrity monitoring, weeks of event growth, battery impact.
Do not treat the numbers above as promises for those workloads. One thing noticed: event file names are second + PID + a random number
below 100,000, so very high event rates in one second could overwrite each other (about 2.5 % loss at 10,000 events in a second in a synthetic
test). Real sensors emit a handful per run, so this is a P3 and was left alone.

## Security review summary

Reviewed by reading and by tests: subprocess use (lists, never `shell=True`), path handling and symlinks (quarantine, integrity, decoys), temp
files (atomic per-PID names), privilege escalation (only fixed text via `lg_run_privileged`; stand-in `pkexec`/`sudo` record attempts and
the tests assert there are none outside the intended calls), config parsing, event and JSON deserialization (plain `json`, no pickle), and
what gets logged. Fuzz tests feed hostile values (quotes, newlines, `$(...)`, `../`, huge strings, NUL, bidi characters) to every
entry point that takes user or file input. No P0 was found.

Limits that remain by design: a program running as your own user can edit your user files, the data folder and the user timers; the
development-checkout sensor cannot tell your edit from a same-user attacker's edit (it reports at information level there and escalates
for world-writable, foreign-owned or untracked-new files). Security here is detection and honesty about what it cannot see.

## CI/CD

`.github/workflows/ci.yml` (lint job: ruff, bandit, shell syntax, shellcheck; test job: pytest with coverage under xvfb on Ubuntu 22.04,
shell suites), `codeql.yml`, and `dependabot.yml`. Read-only token permissions, no secrets, nothing runs as root, no deploy or publish step,
actions pinned to commit SHAs (please confirm those SHAs against the action repositories on the first run; they were not checked against
GitHub from here). **Status: not run on GitHub.**

## Packaging

`tests/test_packaging.py` (13 tests) installs and removes the desktop entry and both user timers in a disposable home, checks upgrade keeps
user data, that failures are reported, and that uninstall removes only LinuxGuardian's own units. Not tested: a `.deb` (none exists), other
distributions, and the real `systemctl --user` on a clean machine.

## Remaining risks and open items

* P2: CI unproven on GitHub (above).
* P2: privileged flows verified only against stubs.
* P3: the weak-coverage GUI dialogs listed above.
* P3: event file name collisions at extreme rates.
* P3: GUI memory (about 186 MB) is typical for GTK4 but was not compared with alternatives.
* Future work, not started and not needed for B: a `.deb`, a longer soak test, a real-malware lab run in a disposable VM (never on this
  laptop), and an independent review.

Nothing from this phase has been pushed or released.

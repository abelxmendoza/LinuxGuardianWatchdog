# Testing LinuxGuardian

Everything here runs as an ordinary user, in disposable folders, without changing your firewall, your processes or your real
`~/.linuxguardian`. Nothing in the test suite asks for a password.

## Run it

```bash
sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 xvfb shellcheck   # xvfb only if you have no display
python3 -m venv --system-site-packages .venv && .venv/bin/pip install -r requirements-dev.txt

cd LinuxGuardianSuiteUI
../.venv/bin/python -m pytest tests -q                        # everything (the GUI tests skip themselves without a display)
xvfb-run -a ../.venv/bin/python -m pytest tests -q            # headless, as CI does it
../.venv/bin/python -m pytest tests -q --cov=../LinuxGuardianSuite --cov=linuxguardian_ui --cov-report=term-missing

cd ..
for t in tests/test_*.sh; do bash "$t"; done                  # shell suites (privileged scripts against stubs)
.venv/bin/ruff check .                                        # static analysis
.venv/bin/bandit -q -ll -c .bandit -r LinuxGuardianSuite LinuxGuardianSuiteUI/linuxguardian_ui
shellcheck -S warning LinuxGuardianSuite/*.sh LinuxGuardianSuiteUI/*.sh
.venv/bin/pip-audit -r requirements-dev.txt
```

## What each kind of test is for

| Kind | Where | What it proves |
|---|---|---|
| Unit | `test_<module>.py` | One function or module does what it says, including malformed, empty and hostile input. |
| Integration | `test_integration_pipeline.py` | The parts agree with each other: sensor to event to classification to notification to Timeline; audit to rating; detection to quarantine to restore. |
| End to end | `test_e2e_workflows.py`, `test_e2e_gui.py` | A user's workflow works through the real scripts and the real window: start up, every tab, scan, accept a risk, quarantine, integrity. |
| Regression | `test_stabilization.py`, and the regression-named tests inside each module | A bug that was found and fixed stays fixed. Each has a comment saying what went wrong. |
| Security | `test_security_inputs.py`, `test_destructive_scripts.py`, `test_ai_safety.py` | Hostile values never execute, never escalate, never crash; kill and delete refuse dangerous input. |
| Failure and recovery | `test_stabilization.py`, `test_self_check.py`, `test_quarantine.py` | A full disk, an unreadable file, corrupt state, a missing tool and an interrupted run fail politely and recover. |
| Packaging | `test_packaging.py` | Install, upgrade and removal in a disposable home keep your data and leave no stray files. |
| Shell | `tests/*.sh` | The privileged scripts' fixed root text and input validation, against stub `pkexec`. |

## Rules the tests live by

* **Never touch the host.** Tests point `HOME`, `LG_HOME` and the `LG_SENSOR_*` hooks at a temp folder. `monkeypatch.undo()` is banned
  (it would silently undo that and aim a test at your real data); a hygiene test enforces it.
* **Dangerous commands are intercepted, not trusted.** `kill` is replaced by a function that only logs; `pkexec` and `sudo` are stand-ins
  that record any attempt.
* **Fixtures clean up.** Tests that create setuid files strip the bit afterwards (a session hook catches stragglers), because the live
  setuid sensor walks `/tmp` and would call them an incident.
* **No real malware, ever.** Quarantine tests use a text marker that a stub scanner treats as "infected".
* **A test that cannot fail is a bug.** Security-relevant checks were mutation-tested: break the guard in a copy, confirm a test fails.

## Not covered by automated tests (honestly)

* Real `apt`, `ufw`, `freshclam`, `rkhunter` and `pkexec` behaviour: the root scripts are tested against stubs. Verify those by hand on a
  disposable Ubuntu machine before relying on a change to them.
* A real ClamAV detection: the scanner is stubbed so no malware is ever handled.
* Real ROS 2 / PX4 / Gazebo workloads and the monitor's behaviour under them.
* Behaviour on distributions other than Ubuntu 22.04 with GNOME on X11.
* The GitHub Actions workflows themselves run only on GitHub; locally they are validated as YAML and their commands are run by hand.

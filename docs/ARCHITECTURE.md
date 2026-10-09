# Architecture

## Design principle

Keep the GUI thin. All real security work happens in standalone shell/python
scripts under `LinuxGuardianSuite/` that:

- can be run standalone from a terminal with no GUI at all
- print human-readable progress plus a machine-readable summary line
- never delete anything outright — destructive actions go through a
  quarantine directory (`~/.linuxguardian/quarantine/`) with a dry-run mode
  on by default

The GUI (`LinuxGuardianSuiteUI/`) is a process-execution shell around these
scripts: it shows buttons/pages, runs the script as a subprocess, and streams
stdout into the UI. This mirrors the macOS original's split between
SwiftUI-as-orchestrator and bash-as-worker.

## Local data

All state lives under `~/.linuxguardian/`:

```
~/.linuxguardian/
├── config                # user config, sourced by config.sh
├── baselines/            # SHA-256 integrity baselines per monitored dir
├── checkpoints/          # resumable scan progress
├── quarantine/           # remediation staging area (never auto-deleted)
├── logs/
└── incidents/            # structured incident records for the UI
```

## Script contract

Every script under `LinuxGuardianSuite/` sources `config.sh` and `utils.sh`
first, supports `-h/--help`, and exits non-zero on failure. Scripts that can
alter the system support `--dry-run` (default) and require an explicit
`--apply` to make changes.

## Privilege model (Updates)

Installing software needs root, and the machine has no passwordless sudo. The
Updates feature therefore never handles a password: `linux_updates.sh --apply`
asks the desktop's own polkit prompt (`pkexec`), and only fixed, hard-coded
package-manager scripts run as root (`tests/test_updates.sh` asserts these
contain no variable or command interpolation, so what runs as root is exactly
what is written in the file).

Deliberate limits:

- `apt-get upgrade`, never `full-upgrade`/`dist-upgrade`/`autoremove`: it can't
  remove packages. Anything that would need that (a GPU driver version change
  is the usual case) is shown as "held back" for the user to review.
- No Stop button during an install. The root side can't be safely interrupted
  (killing dpkg mid-unpack leaves half-configured packages), and the script
  keeps draining the installer's output to a log even if the window is closed,
  so closing the GUI can't SIGPIPE apt/dpkg half-way through.
- Security-only mode reuses `unattended-upgrade`, the same tool that applies
  Ubuntu's daily security patches.
- Release guard: before any install (dry runs included) `update_inventory.py --guard`
  checks every apt source file (one-line and deb822) and every pending package's
  Ubuntu origin against the running release, and fails closed if the release can't
  be determined. It blocks with exit code 3; there is deliberately no override flag.
- Holds (`--hold`/`--unhold`) are the one root action that takes *data* (package
  names). They arrive as positional arguments (`"$@"`), never spliced into the script
  text, are filtered to valid Debian package names in Python and bash, and are
  validated a third time as root. Group patterns are exact on purpose (a `libcu`
  prefix would also hold libcurl4/libcups2 and block *their* security fixes).
  Holds use plain `apt-mark hold`, so apt itself is the source of truth and there's
  no private state to drift.

## Privilege model (scanner: definitions + rootkit check)

Two more fixed root scripts, run the same way (`lg_run_privileged` in `utils.sh` is the
one shared helper; `linux_updates.sh` uses it too):

- `PRIV_SCRIPT_FRESHCLAM`: `freshclam`, nothing else. Exit 126/127 from pkexec means the
  prompt was dismissed: reported as "cancelled", exit code 2, nothing changed.
- `PRIV_SCRIPT_RKHUNTER`: `rkhunter --check --sk --nocolors --no-mail-on-warning`. Opt-in per scan
  (`--rootkit`; a checkbox in the app). Without it, no password prompt ever appears and the
  scan is saved as `rootkit_check: needs_root`.

What is deliberately **not** automated:

- `rkhunter --propupd` is never run by a scan. It tells rkhunter "the system as it is now is the good
  baseline", so run blindly it would bless a compromised system. Ubuntu's `APT_AUTOGEN=false` means the
  baseline goes stale after package updates, so a real run shows many "file properties have changed"
  warnings. They are counted separately and explained. The only path to a refresh is the previewed one
  (`--refresh-rootkit-baseline`, or Review rootkit baseline in the app): `rkhunter_baseline.py` checks every
  warned file against the package that owns it (`dpkg -S` + `dpkg --verify`) and the refresh is offered ONLY
  if every single warning is explained that way. A file no package owns, one that differs from its package,
  a non-file warning, or a count that doesn't add up blocks it, and then no password prompt appears at all.
  The console format of rkhunter was inferred (its detailed log is root-only); the analysis fails closed.
- `rkhunter --update`: dead on Ubuntu (`WEB_CMD=/bin/false`, `UPDATE_MIRRORS=0`).
- Enabling `clamav-freshclam` happens only when the user clicks "Turn on automatic updates" and confirms: `PRIV_SCRIPT_ENABLE_FRESHCLAM` is `systemctl enable --now` for that one unit and nothing else.

Honest bookkeeping: every saved scan records `rootkit_check` as `ran | needs_root | cancelled | not_run`.
"Clean" is only ever shown when it was `ran`. No Stop during the root step (the user can't signal a
root process); the app says so instead of showing a button that doesn't work.

`scanner_health.py` is read-only: definitions age (from `daily.c[lv]d`, not the months-old `main.cvd`),
updater service state, rkhunter baseline age and the last check status. Shown on the Dashboard.

## Security score

`linux_security_audit.sh` is the single place the score is computed: a pass is worth 1, a warning
1/2, a failure 0, and it prints `Rating: N%`. The app only reads that line (`score.py`), so the
CLI and the window can't disagree. Two checks measure whether a scan result can be trusted at all:
virus definitions no older than 2 days, and a rootkit check that has actually run.

## Moving apps between laptops

`app_manifest.py` writes a plain list (apt manual installs with their origin, snaps, flatpaks, the third-party
repositories they came from with credentials stripped, holds). It contains nothing from `$HOME`.
`--plan` recomputes everything on the target; the file is never trusted: names are matched against strict
patterns at three independent layers (planner, `linux_apps.sh`, the root script itself) and each layer is
tested to hold on its own. Import refuses on a different release or CPU, skips hardware-specific packages
(kernel, NVIDIA/CUDA/Jetson, firmware) by name rule even if the file claims otherwise, never adds a repository
or key (third-party apps are listed with the repo they need), never removes (`apt-get install --no-remove`),
and installs classic (unconfined) snaps only when explicitly included.

## Timeline and notifications

`timeline.py` folds identical findings (a count changing doesn't make a finding new) and lets you mark
one as seen; nothing is deleted. The audit only records a finding when it is NEW and records a "Resolved"
event when it goes away (`audit_events.py`). `notify_events.py` announces events newer than its last run,
grouped into one notification, and never replays history on first use.

## File integrity

`integrity.py` (called by `linux_watchdog.sh`) watches ~/Documents and the places malware restarts from:
shell start-up files, ~/.ssh, autostart entries, user systemd units, `/etc/ld.so.preload`, `/etc/passwd`.
Changes are classified modified / new / missing; a new file in a persistence location is a warning, a new
document is information. `.git` internals, caches and the honeypot are skipped. The honeypot is only ever
`stat`ed (hashing it, or scanning it with ClamAV, reads it and used to set off its own alarm), and an access
is reported once. Events are capped per check so a mass change is one summary, not hundreds of files.

## Branding

The palette in `style.css` is sampled from the wolf logo: near-black violet ground, neon-violet
outline (`omega_violet`), amber eyes (`omega_yellow`), ember-orange "WATCHDOG" (`omega_orange`).
`images/LinuxGuardianLogo.png` is the original; the head-only rounded icon is installed into the
user's icon theme by `install_desktop_entry.sh` (`Icon=linuxguardian-watchdog`, matched to the window
by `StartupWMClass`).

## Security events

`events.py` is the one definition of what a security event looks like. Detectors
write small JSON files into `~/.linuxguardian/incidents/`; the required core is
the same four fields the shell helper `lg_record_incident` has always written
(`timestamp`, `category`, `severity`, `message`), plus optional structured fields
(`event`, `status`, `process`, `pid`, `port`, `protocol`, ...) so a future timeline,
notification or anomaly detector doesn't have to parse sentences. Severities stay
`info | warning | critical`: one vocabulary, not two. Old records stay readable.

Detectors that run repeatedly (`linux_exposure.sh --record`) only write an event when
something is **new or changed**, using a small state file, so a daily timer doesn't
bury the timeline in repeats.

## Exposure detection (detection only)

`exposure_inventory.py` reads `ss`, `ip` and the firewall's *readable* state, and never
closes a port, stops a service or changes a rule. It needs no root, and says so where
that limits it:

- Listeners owned by root or another user are reported as "owner not visible", not guessed.
- Firewall allow-rules are root-only. What is readable is whether ufw is enabled and its
  default inbound policy, so coverage is reported as "default-deny, allow-rules can't be
  checked", and a default-deny firewall lowers a finding by one level but never erases it.
- Severity is a small pure function (class of service x scope x firewall) that the tests
  table-check; loopback-only listeners are never findings.

## GUI stack

- **GTK4** — native Linux widget toolkit (the closest equivalent to AppKit/
  SwiftUI on macOS; ships with GNOME and is well supported on KDE/other DEs
  via GTK theming)
- **libadwaita** — GNOME's modern application design layer on top of GTK4
  (adaptive layouts, view switchers, toast notifications) — gives the app a
  native, modern look rather than a generic cross-platform one
- **PyGObject** — Python bindings for GTK4/libadwaita, chosen over C for
  faster iteration while prototyping; a future native rewrite (C or Vala)
  is possible once the feature set stabilizes

## Theme: "Omega Black-Ops"

Ported from the macOS original's terminal theme (`theme_omega_black_ops.sh`):
near-black background (`#0d0d0d`), light-gray text (`#e5e5e5`), purple accent
(`#8c00ff`) for primary/suggested actions, red (`#ff1100`) for destructive
actions and critical status, yellow (`#ffe600`) for warnings. Defined in
`LinuxGuardianSuiteUI/resources/style.css` as GTK4 CSS (`@define-color` +
selectors targeting libadwaita's built-in style classes like
`.suggested-action`/`.destructive-action`), loaded and forced to dark mode in
`main.py` regardless of the system's light/dark setting — the original is a
deliberately dark security-suite look, not a system-theme follower.

## Compatibility notes

This targets libadwaita **1.1+** (Ubuntu 22.04's version), not just the
latest. That ruled out a couple of newer widgets during development:
`Adw.ToolbarView` and `Adw.MessageDialog` need 1.4/1.2 respectively and
aren't used here — `window.py` builds the header/content layout by hand
with a plain `Gtk.Box`, and `dialogs.py` has a small hand-rolled confirm
dialog instead. If you're developing against a newer libadwaita and want to
adopt those, gate it behind a version check rather than replacing them
outright, so older systems don't break.

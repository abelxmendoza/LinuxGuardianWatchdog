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

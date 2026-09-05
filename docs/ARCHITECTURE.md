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

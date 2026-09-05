# LinuxGuardian Watchdog

A free, integrated security platform for Linux desktops — a native port of
[MacGuardianWatchdog](https://github.com/abelxmendoza/MacGuardianWatchdog),
rebuilt for the Linux desktop instead of macOS.

Same idea as the original: real security tools (not just a UI) in one place —
antivirus scanning, rootkit detection, file integrity monitoring, security
posture auditing, and automated remediation — orchestrated by a native
desktop app, with all data kept local to the machine.

> **Status: scaffold / early bootstrap.** This is the initial skeleton —
> directory layout, a working core script or two, and a minimal native UI
> shell. It is not yet feature-complete. See [docs/ROADMAP.md](docs/ROADMAP.md).

## Architecture

Same hybrid split as the macOS original: a native GUI frontend that shells
out to security scripts which do the real work, so the heavy lifting stays
inspectable, scriptable, and usable from a terminal even without the GUI.

| Layer | macOS original | Linux port |
|---|---|---|
| GUI toolkit | SwiftUI (native macOS) | GTK4 + libadwaita (native GNOME/Linux desktop), Python |
| Scan engine | ClamAV + rkhunter | ClamAV + rkhunter (same tools, native on Linux) |
| Scheduling | `launchd` | `systemd` user timers |
| Service management | `launchctl` | `systemctl --user` |
| File integrity | SHA-256 baseline (bash) | SHA-256 baseline (bash, ported as-is — fully portable) |
| Local data dir | `~/.macguardian/` | `~/.linuxguardian/` |
| Firewall checks | macOS Application Firewall | `ufw` / `firewalld` (auto-detected) |
| Behavioral / ML layer | Python (`ai_engine.py`, `ml_engine.py`) | Python, ported later (see roadmap) |

## Repository layout

```
LinuxGuardianWatchdog/
├── LinuxGuardianSuite/       # Shell + Python scripts that do the actual work
│   ├── config.sh             # Shared paths, colors, defaults
│   ├── utils.sh              # Shared logging/helper functions
│   ├── linux_guardian.sh     # ClamAV + rkhunter scan orchestration
│   ├── linux_watchdog.sh     # SHA-256 file integrity baseline + honeypot
│   ├── linux_security_audit.sh  # Scored security posture checks
│   ├── install_scheduler.sh  # Installs systemd user timers for automation
│   └── modules.conf.example
├── LinuxGuardianSuiteUI/     # Native GTK4 / libadwaita desktop app (Python)
│   └── linuxguardian_ui/
├── docs/                     # Architecture notes and roadmap
└── tests/                    # Script sanity tests
```

## Requirements

- A Linux desktop (tested target: GNOME / any GTK4+libadwaten-capable DE)
- `clamav` (`clamscan`, `freshclam`) and `rkhunter` — install via your
  distro's package manager, e.g. `sudo apt install clamav rkhunter`
- Python 3.10+ with PyGObject (`python3-gi`) and `libadwaita-1` for the GUI
- `systemd` (user services) for scheduled scans

## Getting started (scripts only, no GUI yet)

```bash
cd LinuxGuardianSuite
./linux_watchdog.sh --init      # create the file-integrity baseline
./linux_guardian.sh --scan      # run a ClamAV + rkhunter scan
./linux_security_audit.sh       # scored security posture check
```

## Getting started (GUI)

```bash
cd LinuxGuardianSuiteUI
python3 -m pip install -r requirements.txt   # or use your distro's PyGObject package
python3 -m linuxguardian_ui.main
```

## License

MIT — see [LICENSE](LICENSE). Bundles/relies on ClamAV (GPL-2.0) and
rkhunter (GPL-2.0) as external tools, same as the macOS original.

**Disclaimer**: review the code before running it, test in a non-production
environment first, keep backups, prefer dry-run/preview modes, and manually
review anything before it's quarantined or deleted. Misuse can cause data
loss.

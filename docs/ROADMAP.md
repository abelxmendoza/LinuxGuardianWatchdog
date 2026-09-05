# Roadmap

This is a bootstrap scaffold. Rough order of what's left, mirroring the
macOS original's feature set:

## Phase 1 — Core scripts (partially done)
- [x] `config.sh`, `utils.sh` — shared shell helpers
- [x] `linux_watchdog.sh` — SHA-256 integrity baseline + honeypot
- [x] `linux_guardian.sh` — ClamAV + rkhunter scan orchestration
- [x] `linux_security_audit.sh` — scored posture checks (firewall, SSH, updates, sudoers)
- [ ] `linux_blueteam.sh` — process/network anomaly detection
- [ ] `linux_remediation.sh` — dry-run-first quarantine & fix suggestions
- [ ] `threat_intel_feeds.sh` — Abuse.ch / URLhaus IOC matching

## Phase 2 — Automation
- [x] `install_scheduler.sh` — systemd user timers (launchd equivalent)
- [ ] Email/webhook alerting module

## Phase 3 — Native GUI (GTK4 + libadwaita)
- [x] App shell, sidebar navigation, dashboard page stub
- [ ] Wire dashboard buttons to real script execution + live output pane
- [ ] Scan history / incident view
- [ ] Settings page (monitored paths, schedule, thresholds)
- [ ] System tray / background indicator (via `AppIndicator3` or GNOME Shell extension)
- [ ] Packaging: Flatpak manifest, and/or `.deb`/AUR package

## Phase 4 — Behavioral / ML layer (later)
- [ ] Port `ai_engine.py` / `ml_engine.py` concepts to a Linux-appropriate
      anomaly detector (e.g. watching `journald` instead of macOS unified log)
- [ ] `event_bus.py` — WebSocket daemon for real-time UI updates

## Notes on Linux-specific swaps
- `launchd` → `systemd --user` timers/services
- macOS unified log (`log show`) → `journalctl`
- macOS Application Firewall → `ufw`/`firewalld` (detect whichever is active)
- Gatekeeper/notarization checks → not applicable; consider AppArmor/SELinux
  status checks instead in the security audit
- Browser cache cleanup paths differ per-distro/per-browser; needs its own pass

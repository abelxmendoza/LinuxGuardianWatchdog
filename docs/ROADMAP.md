# Roadmap

This is a bootstrap scaffold. Rough order of what's left, mirroring the
macOS original's feature set:

## Phase 1 — Core scripts (partially done)
- [x] `config.sh`, `utils.sh` — shared shell helpers
- [x] `linux_watchdog.sh` — SHA-256 integrity baseline + honeypot
- [x] `linux_guardian.sh` — ClamAV + rkhunter scan orchestration
- [x] `linux_security_audit.sh` — scored posture checks (firewall, SSH, updates, sudoers)
- [x] `linux_process_manager.sh` — process killer (list, SIGTERM/SIGKILL by PID or name)
- [x] `linux_cache_cleanup.sh` — cache cleaner (browser + system caches, dry-run by default)
- [ ] `linux_blueteam.sh` — process/network anomaly detection
- [ ] `linux_remediation.sh` — dry-run-first quarantine & fix suggestions
- [ ] `threat_intel_feeds.sh` — Abuse.ch / URLhaus IOC matching

## Phase 2 — Automation
- [x] `install_scheduler.sh` — systemd user timers (launchd equivalent)
- [ ] Email/webhook alerting module

## Phase 3 — Native GUI (GTK4 + libadwaita)
- [x] App shell, view switcher, dashboard page wired to real scripts + live output pane
- [x] "Omega Black-Ops" theme (dark bg, purple/red/yellow accents) ported from the
      macOS original's `theme_omega_black_ops.sh` terminal theme
- [x] Processes page — the process killer (list, filter, sort, End/Force Kill with confirm dialog)
- [x] Cache Cleaner page — scan + clear with size preview and confirm dialog
- [x] Updates page — pending security/system/third-party/snap updates, one-click install via
      polkit, held-back packages surfaced (never forced), reboot-required notice
- [x] Security Score now checks automatic updates are *enabled* (not just installed), pending
      security updates, and restart-needed
- [x] Updates: release guard — refuses to install if any update source or pending package is for a
      different Ubuntu release than the one running (no override flag)
- [x] Updates: pinned stacks — freeze ROS 2 / Gazebo / NVIDIA+CUDA with `apt-mark hold`, honored by
      this app, Ubuntu's Software Updater and the automatic updater alike
- [ ] Updates: notify (desktop notification) when security updates have been pending for days
- [ ] Security Score: warn when the release is nearing end of standard support
- [x] Exposure page: what's listening, on which interface, who can reach it, firewall state, who is
      connected now. Detection only; says what it can't see without root instead of guessing
- [x] Shared security-event format (`events.py`); exposure detection records NEW/CHANGED exposures once
- [x] Fixed: the audit reported "no firewall" on machines where ufw was active (it asked `ufw status`,
      which needs root); detection now uses what a normal user can read
- [ ] Incident timeline page reading `events.read_events()` (the format and reader already exist)
- [ ] ROS-aware firewall setup (preview-first; allow ROS 2/DDS and Tailscale before default-deny)
- [ ] Real integration tests for the privileged paths (apt, apt-mark, unattended-upgrade) inside a
      throwaway Ubuntu container; today they're verified against stubs
- [ ] Export/import a manifest of installed apps and repos for setting up another machine
- [ ] Updates: toggle automatic security updates from the app (needs a polkit-guarded write)
- [ ] Scan history / incident timeline view (incidents are already recorded to
      `~/.linuxguardian/incidents/*.json` by every script — just needs a page)
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

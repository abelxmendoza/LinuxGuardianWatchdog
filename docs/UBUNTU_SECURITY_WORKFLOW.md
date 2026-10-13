# Ubuntu security workflow

1. Run the dashboard audit. Unknown or unverified results require follow-up; they are not proof a protection is off or on.
2. Apply Ubuntu security updates with Software Updater and restart when required. The audit checks APT periodic settings and its timer, not update history or repository coverage.
3. Inspect the firewall with `sudo ufw status verbose`. Preserve needed remote-access rules before enabling or changing it. A firewall front-end being active does not prove the rules are appropriate.
4. Keep antivirus definitions current. On Ubuntu installations with the packaged updater, inspect `systemctl status clamav-freshclam` and enable it with `sudo systemctl enable --now clamav-freshclam` if appropriate. Verify its logs and definition date afterward.
5. Run a scan. Full mode expands coverage within the target, normally the home folder. Review errors, skipped checks, and the rootkit report. If root privileges are required, run `sudo rkhunter --check --sk` in a terminal. Warnings need investigation, not automatic deletion.
6. Review unfamiliar processes and listening services. Disable unwanted services in their settings; killing a process is not a persistent configuration fix.
7. Create a Documents baseline with `LinuxGuardianSuite/linux_watchdog.sh --init`, then use Check File Integrity. A baseline records current file contents and does not establish trust. Keep backups separately.

Machine-specific reports, findings, and baselines belong in local runtime storage, never in this repository.

References:
- https://documentation.ubuntu.com/security/security-updates/
- https://documentation.ubuntu.com/server/how-to/security/firewalls/index.html
- https://docs.clamav.net/manual/Usage/Configuration.html

## Copy security reports

The copy icon in the window header opens a combined **Security posture & diagnostics** report. Its **Copy All** button includes loaded page summaries, collapsed technical details, dashboard session activity, complete process/update/cache inventories, and available saved scanner logs. It uses captured data; it does not start a new check. Check timestamps and coverage before relying on it.

- Dashboard: **Copy Audit**, **Copy Scan Report**, **Copy All Activity**, and **Copy All Terminal Output**. Session reports keep earlier actions until the app closes.
- Activity cards: **Copy All Findings** and **Copy Details** include complete grouped findings, even when the on-screen preview omits a long list.
- Hardening: copy the whole page or one check's technical details. Review dialogs also offer **Copy All Details**.
- VPN, Updates, Apps, and Incidents: **Copy All Page Details** includes current text and collapsed details. Updates also has **Copy All Installer Output**.
- Processes: copy the overview, a group, or the full **Technical report**, regardless of the current filters.
- Cache Cleaner: **Copy All** includes locations and retained scan/cleanup logs. **Technical output** exposes failure messages too.

Reports may include usernames, local paths, command lines, and network addresses. Review them before sharing. Copying stays local and makes no system changes. A live report is partial; attaching to an existing scan cannot recover earlier output, so review its saved scanner logs when available.

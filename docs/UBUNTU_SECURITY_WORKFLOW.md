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

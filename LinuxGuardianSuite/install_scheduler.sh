#!/usr/bin/env bash
# install_scheduler.sh — installs systemd --user timers for scheduled scans.
# This is the Linux equivalent of the macOS original's launchd plists.
#
# Usage:
#   install_scheduler.sh --install     Install the daily scan timer
#   install_scheduler.sh --uninstall   Remove it
#   install_scheduler.sh -h | --help
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"
# shellcheck source=utils.sh
source "$SCRIPT_DIR/utils.sh"

UNIT_DIR="$HOME/.config/systemd/user"
SERVICE_NAME="linuxguardian-scan.service"
TIMER_NAME="linuxguardian-scan.timer"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//;1d'; }

install_units() {
  mkdir -p "$UNIT_DIR"

  cat > "$UNIT_DIR/$SERVICE_NAME" <<EOF
[Unit]
Description=LinuxGuardian daily security scan

[Service]
Type=oneshot
ExecStart=$SCRIPT_DIR/linux_guardian.sh --scan %h
ExecStartPost=$SCRIPT_DIR/linux_watchdog.sh --check
EOF

  cat > "$UNIT_DIR/$TIMER_NAME" <<EOF
[Unit]
Description=Run LinuxGuardian scan daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl --user daemon-reload
  systemctl --user enable --now "$TIMER_NAME"
  lg_ok "Installed and enabled $TIMER_NAME (systemctl --user list-timers to verify)"
}

uninstall_units() {
  systemctl --user disable --now "$TIMER_NAME" 2>/dev/null || true
  rm -f "$UNIT_DIR/$SERVICE_NAME" "$UNIT_DIR/$TIMER_NAME"
  systemctl --user daemon-reload
  lg_ok "Removed scheduled scan timer."
}

case "${1:-}" in
  --install) install_units ;;
  --uninstall) uninstall_units ;;
  -h|--help|"") usage; exit 0 ;;
  *) lg_error "Unknown option: $1"; usage; exit 1 ;;
esac

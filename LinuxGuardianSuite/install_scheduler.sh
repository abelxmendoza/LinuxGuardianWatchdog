#!/usr/bin/env bash
# install_scheduler.sh — installs systemd --user timers for scheduled scans.
# This is the Linux equivalent of the macOS original's launchd plists.
#
# Usage:
#   install_scheduler.sh --install     Install the daily scan timer
#   install_scheduler.sh --uninstall   Remove it
#   install_scheduler.sh --install-sensors    Live monitoring: run the blue-team sensors every 5 minutes
#   install_scheduler.sh --uninstall-sensors  Turn live monitoring off
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

usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

install_units() {
  mkdir -p "$UNIT_DIR"

  cat > "$UNIT_DIR/$SERVICE_NAME" <<EOF
[Unit]
Description=LinuxGuardian daily security scan

[Service]
Type=oneshot
# Gentle on the battery: low CPU and disk priority, and only files changed since the last scan.
Nice=10
IOSchedulingClass=idle
# A scan missed while the laptop was off or asleep catches up on the next start; wait 15 minutes first so it never
# competes with logging in or waking up.
ExecStartPre=/bin/sleep 900
ExecStart=$SCRIPT_DIR/linux_guardian.sh --scan --changed %h
ExecStartPost=-$SCRIPT_DIR/linux_watchdog.sh --check
ExecStartPost=-$SCRIPT_DIR/linux_exposure.sh --record
ExecStartPost=-$SCRIPT_DIR/linux_security_audit.sh
ExecStartPost=-$SCRIPT_DIR/notify_events.py --send
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

  if ! systemctl --user daemon-reload || ! systemctl --user enable --now "$TIMER_NAME"; then
    lg_error "Couldn't turn on $TIMER_NAME (is your user systemd session running?). The unit files are in $UNIT_DIR; run '$0 --uninstall' to clean up."
    return 1
  fi
  # Our own new files must not be reported by the daily integrity check as something that appeared in a start-up location.
  python3 "$SCRIPT_DIR/integrity.py" --accept "$UNIT_DIR/$SERVICE_NAME" "$UNIT_DIR/$TIMER_NAME" >/dev/null 2>&1 || true
  lg_ok "Installed and enabled $TIMER_NAME (systemctl --user list-timers to verify)"
}

SENSORS_SERVICE="linuxguardian-sensors.service"
SENSORS_TIMER="linuxguardian-sensors.timer"

install_sensors() {
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT_DIR/$SENSORS_SERVICE" <<EOF
[Unit]
Description=LinuxGuardian live monitoring (blue-team sensors)

[Service]
Type=oneshot
# Light and quiet: low CPU and disk priority, finishes in a second or two.
Nice=15
IOSchedulingClass=idle
ExecStart=$SCRIPT_DIR/sensors.py --run
ExecStartPost=-$SCRIPT_DIR/notify_events.py --send
EOF
  cat > "$UNIT_DIR/$SENSORS_TIMER" <<EOF
[Unit]
Description=Run LinuxGuardian live monitoring every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF
  if ! systemctl --user daemon-reload || ! systemctl --user enable --now "$SENSORS_TIMER"; then
    lg_error "Couldn't turn on live monitoring (is your user systemd session running?). Run '$0 --uninstall-sensors' to clean up."
    return 1
  fi
  python3 "$SCRIPT_DIR/integrity.py" --accept "$UNIT_DIR/$SENSORS_SERVICE" "$UNIT_DIR/$SENSORS_TIMER" >/dev/null 2>&1 || true
  lg_ok "Live monitoring is on ($SENSORS_TIMER)."
}

uninstall_sensors() {
  systemctl --user disable --now "$SENSORS_TIMER" 2>/dev/null || true
  # ${VAR:?} makes the shell stop with an error instead of ever deleting a bare "/" if a variable were empty.
  rm -f "${UNIT_DIR:?}/${SENSORS_SERVICE:?}" "${UNIT_DIR:?}/${SENSORS_TIMER:?}"
  python3 "$SCRIPT_DIR/integrity.py" --forget "$UNIT_DIR/$SENSORS_SERVICE" "$UNIT_DIR/$SENSORS_TIMER" >/dev/null 2>&1 || true
  systemctl --user daemon-reload
  lg_ok "Live monitoring is off."
}

uninstall_units() {
  systemctl --user disable --now "$TIMER_NAME" 2>/dev/null || true
  rm -f "$UNIT_DIR/$SERVICE_NAME" "$UNIT_DIR/$TIMER_NAME"
  python3 "$SCRIPT_DIR/integrity.py" --forget "$UNIT_DIR/$SERVICE_NAME" "$UNIT_DIR/$TIMER_NAME" >/dev/null 2>&1 || true
  systemctl --user daemon-reload
  lg_ok "Removed scheduled scan timer."
}

case "${1:-}" in
  --install) install_units ;;
  --uninstall) uninstall_units ;;
  --install-sensors) install_sensors ;;
  --uninstall-sensors) uninstall_sensors ;;
  -h|--help|"") usage; exit 0 ;;
  *) lg_error "Unknown option: $1"; usage; exit 1 ;;
esac

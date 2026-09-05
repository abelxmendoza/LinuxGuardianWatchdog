#!/usr/bin/env bash
# install_desktop_entry.sh — registers LinuxGuardian Watchdog as a launchable
# app: app menu entry, a Desktop shortcut, and a GNOME dock (favorites) pin.
#
# Usage:
#   install_desktop_entry.sh --install
#   install_desktop_entry.sh --uninstall
set -uo pipefail

APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
APP_ID="linuxguardian-watchdog"
APPS_DIR="$HOME/.local/share/applications"
DESKTOP_FILE="$APPS_DIR/$APP_ID.desktop"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//;1d'; }

install_entry() {
  mkdir -p "$APPS_DIR"
  cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=LinuxGuardian Watchdog
Comment=Native Linux security suite - antivirus, integrity monitoring, security audit
Exec=$APP_DIR/run_ui.sh
Icon=$APP_DIR/resources/linuxguardian.svg
Terminal=false
Categories=System;Security;Utility;
StartupNotify=true
EOF
  chmod +x "$APP_DIR/run_ui.sh" "$DESKTOP_FILE"
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS_DIR"

  local desk
  desk="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"
  if [ -d "$desk" ]; then
    cp "$DESKTOP_FILE" "$desk/LinuxGuardian Watchdog.desktop"
    chmod +x "$desk/LinuxGuardian Watchdog.desktop"
    command -v gio >/dev/null 2>&1 && gio set "$desk/LinuxGuardian Watchdog.desktop" metadata::trusted true
    echo "Desktop shortcut: $desk/LinuxGuardian Watchdog.desktop"
  fi

  if command -v gsettings >/dev/null 2>&1 && [[ "${XDG_CURRENT_DESKTOP:-}" == *GNOME* || -n "$(command -v gnome-shell)" ]]; then
    current="$(gsettings get org.gnome.shell favorite-apps 2>/dev/null || echo "[]")"
    if [[ "$current" != *"$APP_ID.desktop"* ]]; then
      python3 - "$APP_ID.desktop" "$current" <<'PYEOF'
import ast, subprocess, sys
entry, current = sys.argv[1], sys.argv[2]
apps = ast.literal_eval(current)
apps.append(entry)
new_val = "[" + ", ".join(f"'{a}'" for a in apps) + "]"
subprocess.check_call(["gsettings", "set", "org.gnome.shell", "favorite-apps", new_val])
PYEOF
      echo "Pinned to GNOME dock favorites."
    fi
  else
    echo "Non-GNOME desktop detected: pin the app to your dock/taskbar manually" \
         "(the app menu entry '$APP_ID' is installed and can usually be" \
         "right-clicked and pinned from there)."
  fi

  echo "Installed. Launch from the app menu, Desktop icon, or dock."
}

uninstall_entry() {
  rm -f "$DESKTOP_FILE"
  local desk
  desk="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"
  rm -f "$desk/LinuxGuardian Watchdog.desktop"
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS_DIR"
  echo "Removed app menu entry and Desktop shortcut. (Dock pin, if any, must be" \
       "unpinned manually.)"
}

case "${1:-}" in
  --install) install_entry ;;
  --uninstall) uninstall_entry ;;
  -h|--help|"") usage; exit 0 ;;
  *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
esac

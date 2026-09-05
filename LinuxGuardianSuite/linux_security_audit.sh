#!/usr/bin/env bash
# linux_security_audit.sh — scored security posture check.
#
# Usage:
#   linux_security_audit.sh
#   linux_security_audit.sh -h | --help
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"
# shellcheck source=utils.sh
source "$SCRIPT_DIR/utils.sh"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  grep '^#' "$0" | sed 's/^# \{0,1\}//;1d'
  exit 0
fi

PASS=0
FAIL=0
WARN=0

check() {
  local label="$1" status="$2" detail="${3:-}"
  case "$status" in
    pass) lg_ok "$label"; PASS=$((PASS+1)) ;;
    warn) lg_warn "$label${detail:+ — $detail}"; WARN=$((WARN+1))
          lg_record_incident "audit" "warning" "$label${detail:+ — $detail}" ;;
    fail) lg_error "$label${detail:+ — $detail}"; FAIL=$((FAIL+1))
          lg_record_incident "audit" "critical" "$label${detail:+ — $detail}" ;;
  esac
}

echo "${LG_C_BOLD}LinuxGuardian Security Audit${LG_C_RESET}"
echo "================================"

# Firewall
fw="$(lg_detect_firewall)"
case "$fw" in
  unknown) check "Firewall status could not be verified" warn "inspect with sudo ufw status verbose; preserve required remote-access rules before changes" ;;
  none) check "No active firewall detected" warn "review required services and firewall configuration" ;;
  *) check "Firewall front-end active ($fw)" pass "rules still require review" ;;
esac

# SSH root login
if [ -f /etc/ssh/sshd_config ]; then
  if grep -Eq '^\s*PermitRootLogin\s+(no|prohibit-password)' /etc/ssh/sshd_config; then
    check "SSH root login restricted" pass
  else
    check "SSH root login not explicitly restricted" warn "set PermitRootLogin no in /etc/ssh/sshd_config"
  fi
else
  check "sshd not installed" pass
fi

# Automatic updates
if command -v apt-config >/dev/null 2>&1; then
  periodic="$(apt-config dump 2>/dev/null)"
  if command -v unattended-upgrade >/dev/null 2>&1 &&
      ! grep -Eq '^APT::Periodic::Enable "0";' <<< "$periodic" &&
      grep -Eq '^APT::Periodic::Update-Package-Lists "[1-9][0-9]*";' <<< "$periodic" &&
      grep -Eq '^APT::Periodic::Unattended-Upgrade "[1-9][0-9]*";' <<< "$periodic" &&
      systemctl is-enabled --quiet apt-daily-upgrade.timer 2>/dev/null &&
      systemctl is-active --quiet apt-daily-upgrade.timer 2>/dev/null; then
    check "Automatic update settings and timer configured" pass
  else
    check "Automatic updates not fully verified" warn "review APT periodic settings and apt-daily-upgrade.timer"
  fi
  echo "Update configuration does not prove recent updates succeeded; review unattended-upgrades logs."
elif command -v dnf >/dev/null 2>&1 && systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null; then
  check "Automatic update timer configured (dnf-automatic)" pass
else
  check "No automatic update mechanism verified" warn "review your distribution's update settings"
fi

# LUKS / disk encryption (best-effort check)
if command -v lsblk >/dev/null 2>&1 && lsblk -o TYPE 2>/dev/null | grep -q crypt; then
  check "Disk encryption (LUKS) detected on at least one volume" pass
else
  check "No LUKS-encrypted volume detected" warn "consider full-disk encryption"
fi

# Mandatory access control
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
  check "SELinux enforcing" pass
elif command -v aa-status >/dev/null 2>&1 && aa-status --enabled 2>/dev/null; then
  check "AppArmor enabled" pass
else
  check "No mandatory access control (SELinux/AppArmor) enforcing" warn
fi

# Passwordless sudoers
if sudo_rules="$(sudo -l -n 2>/dev/null)"; then
  if grep -q NOPASSWD <<< "$sudo_rules"; then
    check "Passwordless sudo entries found for current user" warn "review /etc/sudoers.d/"
  else
    check "No passwordless sudo entries listed for current user" pass
  fi
else
  check "Sudo policy could not be verified without authentication" warn "review sudo -l in a terminal"
fi

echo "================================"
TOTAL=$((PASS+FAIL+WARN))
echo "Score: ${LG_C_GREEN}$PASS pass${LG_C_RESET}, ${LG_C_YELLOW}$WARN warn${LG_C_RESET}, ${LG_C_RED}$FAIL fail${LG_C_RESET} (of $TOTAL checks)"

[ "$FAIL" -eq 0 ]

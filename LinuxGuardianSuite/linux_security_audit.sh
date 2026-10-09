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
  awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
  exit 0
fi

PASS=0
FAIL=0
WARN=0
# Findings are collected and turned into events once, at the end, by audit_events.py: only NEW
# findings (and resolved ones) become events, so re-running the audit doesn't flood the timeline.
FINDINGS="$(mktemp)"
trap 'rm -f "$FINDINGS"' EXIT

check() {
  local label="$1" status="$2" detail="${3:-}"
  case "$status" in
    pass) lg_ok "$label"; PASS=$((PASS+1)) ;;
    warn) lg_warn "$label${detail:+ — $detail}"; WARN=$((WARN+1))
          printf 'warning\t%s\n' "$label${detail:+ — $detail}" >> "$FINDINGS" ;;
    fail) lg_error "$label${detail:+ — $detail}"; FAIL=$((FAIL+1))
          printf 'critical\t%s\n' "$label${detail:+ — $detail}" >> "$FINDINGS" ;;
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

# Updates. One read-only, no-network inventory call feeds all three checks.
# (Installed != enabled: the old check passed merely because the
# unattended-upgrades package existed, even with the timer switched off.)
upd="$(timeout 30 python3 "$SCRIPT_DIR/update_inventory.py" --summary --no-snap 2>/dev/null || true)"
upd_get() { tr ' ' '\n' <<<"$upd" | sed -n "s/^$1=//p"; }

if [ -n "$upd" ] && [ "$(upd_get apt_ok)" = "1" ]; then
  if [ "$(upd_get auto_security)" = "on" ]; then
    check "Automatic security updates are on (unattended-upgrades, daily)" pass
  else
    check "Automatic security updates are NOT enabled" warn "enable: sudo dpkg-reconfigure -plow unattended-upgrades"
  fi
  echo "Update configuration does not prove recent updates succeeded; review unattended-upgrades logs."

  sec_pending="$(upd_get security)"
  if [ "${sec_pending:-0}" -eq 0 ]; then
    check "No pending security updates" pass
  else
    check "$sec_pending security update(s) pending" warn "install them from the Updates tab"
  fi

  if [ "$(upd_get reboot)" = "1" ]; then
    check "Restart needed to finish applying updates" warn "restart when convenient"
  else
    check "No restart pending from updates" pass
  fi
elif [ -n "$upd" ]; then
  check "Could not check for pending updates (apt query failed)" warn "try: sudo apt update"
elif command -v dnf >/dev/null 2>&1 && systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null; then
  check "Automatic update timer configured (dnf-automatic)" pass
else
  check "No automatic update mechanism verified" warn "review your distribution's update settings"
fi

# Network exposure: anything reachable from the network beyond this laptop.
# Read-only, no root. (Severity already accounts for the firewall: see
# exposure_inventory.py.)
exposure="$(timeout 20 python3 "$SCRIPT_DIR/exposure_inventory.py" --summary 2>/dev/null || true)"
exp_get() { tr ' ' '\n' <<<"$exposure" | sed -n "s/^$1=//p"; }
if [ -n "$exposure" ] && [ "$(exp_get ss_ok)" = "1" ]; then
  exp_crit="$(exp_get critical)"
  exp_warn="$(exp_get warning)"
  exp_top="$(exp_get top)"
  if [ "${exp_crit:-0}" -gt 0 ]; then
    check "$exp_crit service(s) exposed to the network (e.g. $exp_top)" fail "see the Exposure tab"
  elif [ "${exp_warn:-0}" -gt 0 ]; then
    check "$exp_warn service(s) reachable from the network (e.g. $exp_top)" warn "see the Exposure tab"
  else
    check "No risky services reachable from the network" pass
  fi
fi

# Can a scan result be trusted? Stale virus definitions or a rootkit scanner that never
# ran make "no malware found" weaker than it sounds. Read-only, no root (scanner_health.py).
health="$(timeout 20 python3 "$SCRIPT_DIR/scanner_health.py" --summary 2>/dev/null || true)"
health_get() { tr ' ' '\n' <<<"$health" | sed -n "s/^$1=//p"; }
if [ -n "$health" ]; then
  if command -v clamscan >/dev/null 2>&1 || [ "$(health_get definitions)" != "missing" ]; then
    case "$(health_get definitions)" in
      ok) check "Virus definitions are current" pass ;;
      warning|critical)
        days=$(( $(health_get definitions_age_sec) / 86400 ))
        check "Virus definitions are $days days old" warn "press Update Definitions on the Dashboard" ;;
      *) check "No virus definitions found" warn "press Update Definitions on the Dashboard" ;;
    esac
  fi
  if [ "$(health_get rkhunter)" = "installed" ]; then
    case "$(health_get rootkit_last)" in
      ran) check "Rootkit check has run (rkhunter)" pass ;;
      *) check "Rootkit check has not run yet" warn "tick 'Include rootkit check' and run a scan" ;;
    esac
  fi
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

python3 "$SCRIPT_DIR/audit_events.py" < "$FINDINGS" 2>/dev/null || true

# Rating: a warning is half a pass (it is a real gap, but not a broken system); a fail is nothing.
# Rounded half up. The app shows this number, so it is computed in exactly one place.
if [ "$TOTAL" -gt 0 ]; then
  echo "Rating: $(( (200 * PASS + 100 * WARN + TOTAL) / (2 * TOTAL) )) of 100"
fi

[ "$FAIL" -eq 0 ]

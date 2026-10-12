#!/usr/bin/env bash
# linux_hardening.sh — the hardening fixes that need root (one password prompt each, fixed scripts).
#
# Usage:
#   linux_hardening.sh --apply FIX     FIX is one of: sysctl, ufw_ipv6, ufw_logging
#   linux_hardening.sh --undo FIX      Put back what --apply replaced
#   linux_hardening.sh --check         The whole checklist (same as hardening.py --check)
#   linux_hardening.sh -h | --help
#
# Fixes that don't need root (screen lock, Screen Sharing, file permissions) run as you through
# hardening.py. Exit: 0 ok, 1 error, 2 cancelled, 3 refused.
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"
# shellcheck source=utils.sh
source "$SCRIPT_DIR/utils.sh"

usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

# What runs as root. FIXED text. Nothing but the allow-listed words below is ever taken from outside.
PRIV_SYSCTL_APPLY='
f=/etc/sysctl.d/99-linuxguardian-hardening.conf
umask 022
{
  printf "%s\n" "# Written by LinuxGuardian Watchdog. Delete this file (or use Undo in the app) to remove it."
  printf "%s\n" "net.ipv4.conf.all.send_redirects = 0" "net.ipv4.conf.default.send_redirects = 0"
  printf "%s\n" "net.ipv4.conf.all.accept_redirects = 0" "net.ipv4.conf.default.accept_redirects = 0"
  printf "%s\n" "net.ipv6.conf.all.accept_redirects = 0" "net.ipv6.conf.default.accept_redirects = 0"
  printf "%s\n" "net.ipv4.conf.all.accept_source_route = 0" "net.ipv4.conf.default.accept_source_route = 0"
  printf "%s\n" "net.ipv6.conf.all.accept_source_route = 0"
  printf "%s\n" "net.ipv4.tcp_syncookies = 1" "net.ipv4.icmp_echo_ignore_broadcasts = 1" "net.ipv4.icmp_ignore_bogus_error_responses = 1"
  printf "%s\n" "kernel.dmesg_restrict = 1" "fs.protected_hardlinks = 1" "fs.protected_symlinks = 1" "kernel.randomize_va_space = 2"
} > "$f" || exit 1
exec sysctl -e -p "$f"
'
# Undo: arguments are KEY VALUE pairs taken from what was recorded before; every key must be one we set, every value one digit.
PRIV_SYSCTL_UNDO='
if [ $(( $# % 2 )) -ne 0 ]; then echo "keys and values must come in pairs" >&2; exit 2; fi
n=$#
while [ "$n" -gt 0 ]; do
  k=$1; v=$2
  shift 2
  case "$k" in
    net.ipv4.conf.all.send_redirects|net.ipv4.conf.default.send_redirects|net.ipv4.conf.all.accept_redirects|net.ipv4.conf.default.accept_redirects|net.ipv6.conf.all.accept_redirects|net.ipv6.conf.default.accept_redirects|net.ipv4.conf.all.accept_source_route|net.ipv4.conf.default.accept_source_route|net.ipv6.conf.all.accept_source_route|net.ipv4.tcp_syncookies|net.ipv4.icmp_echo_ignore_broadcasts|net.ipv4.icmp_ignore_bogus_error_responses|kernel.dmesg_restrict|fs.protected_hardlinks|fs.protected_symlinks|kernel.randomize_va_space) ;;
    *) echo "refusing unknown setting" >&2; exit 2 ;;
  esac
  case "$v" in [0-9]) ;; *) echo "refusing value" >&2; exit 2 ;; esac
  set -- "$@" "$k" "$v"
  n=$((n-2))
done
rc=0
while [ "$#" -gt 0 ]; do
  sysctl -e -w "$1=$2" || rc=1
  shift 2
done
rm -f /etc/sysctl.d/99-linuxguardian-hardening.conf
exit $rc
'
PRIV_UFW_IPV6_APPLY='
f=/etc/default/ufw
if grep -q "^IPV6=" "$f"; then
  sed -i "s/^IPV6=.*/IPV6=yes/" "$f" || exit 1
else
  echo "IPV6=yes" >> "$f" || exit 1
fi
exec ufw reload
'
PRIV_UFW_IPV6_UNDO='
f=/etc/default/ufw
sed -i "s/^IPV6=.*/IPV6=no/" "$f" || exit 1
exec ufw reload
'
PRIV_UFW_LOGGING_APPLY='exec ufw logging low'
PRIV_UFW_LOGGING_UNDO='
case "$1" in off|low|medium|high|full) ;; *) echo "refusing log level" >&2; exit 2 ;; esac
exec ufw logging "$1"
'

MODE="" FIX=""
case "${1:-}" in
  --apply|--undo) MODE="${1#--}"; FIX="${2:-}" ;;
  --check) exec python3 "$SCRIPT_DIR/hardening.py" --check ;;
  -h|--help|"") usage; exit 0 ;;
  *) lg_error "Unknown option: $1"; usage; exit 1 ;;
esac
case "$FIX" in
  sysctl|ufw_ipv6|ufw_logging) ;;
  *) lg_error "Unknown fix '$FIX'. Fixes that don't need a password run through hardening.py."; exit 3 ;;
esac

HP="$SCRIPT_DIR/hardening.py"
log_dir="$LG_LOG_DIR/hardening"; mkdir -p "$log_dir"
log="$log_dir/$MODE-$FIX-$(date '+%Y%m%d-%H%M%S').log"

run_root() {
  trap '' PIPE
  lg_run_privileged "$@" 2>&1 | lg_tee_log "$log"
  return "${PIPESTATUS[0]}"
}

if [ "$MODE" = "apply" ]; then
  prev="$(python3 "$HP" --snapshot "$FIX")"
  case "$FIX" in
    sysctl) script="$PRIV_SYSCTL_APPLY" ;;
    ufw_ipv6) script="$PRIV_UFW_IPV6_APPLY" ;;
    ufw_logging) script="$PRIV_UFW_LOGGING_APPLY" ;;
  esac
  lg_info "Applying '$FIX' (the desktop will ask for your password)..."
  run_root "$script"; rc=$?
  case "$rc" in
    0) python3 "$HP" --record "$FIX" "$prev"
       lg_ok "Done. You can undo it from the Hardening tab."
       lg_record_incident "maintenance" "info" "Hardening applied: $FIX" ;;
    126|127) lg_warn "Cancelled: the password prompt was dismissed. Nothing was changed."; exit 2 ;;
    *) lg_error "That didn't work. See $log"; exit 1 ;;
  esac
else
  mapfile -t uargs < <(python3 "$HP" --undo-args "$FIX")
  case "$FIX" in
    sysctl)
      [ "${#uargs[@]}" -gt 0 ] || { lg_error "Nothing recorded to undo."; exit 3; }
      script="$PRIV_SYSCTL_UNDO" ;;
    ufw_ipv6) script="$PRIV_UFW_IPV6_UNDO"; uargs=() ;;
    ufw_logging)
      [ "${#uargs[@]}" -eq 1 ] || { lg_error "Nothing recorded to undo."; exit 3; }
      script="$PRIV_UFW_LOGGING_UNDO" ;;
  esac
  lg_info "Undoing '$FIX' (the desktop will ask for your password)..."
  run_root "$script" ${uargs[@]+"${uargs[@]}"}; rc=$?
  case "$rc" in
    0) python3 "$HP" --forget "$FIX"; lg_ok "Put back as it was."
       lg_record_incident "maintenance" "info" "Hardening undone: $FIX" ;;
    126|127) lg_warn "Cancelled: the password prompt was dismissed. Nothing was changed."; exit 2 ;;
    *) lg_error "That didn't work. See $log"; exit 1 ;;
  esac
fi

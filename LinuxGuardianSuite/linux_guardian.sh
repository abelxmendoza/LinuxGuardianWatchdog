#!/usr/bin/env bash
# linux_guardian.sh — ClamAV + rkhunter scan orchestration.
#
# Usage:
#   linux_guardian.sh --scan [PATH]     Run ClamAV + rkhunter against PATH (default: $HOME)
#   linux_guardian.sh --update          Update virus/rootkit definitions
#   linux_guardian.sh -h | --help
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"
# shellcheck source=utils.sh
source "$SCRIPT_DIR/utils.sh"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//;1d'; }

case "${1:-}" in
  --scan) MODE="scan"; TARGET="${2:-$HOME}" ;;
  --update) MODE="update" ;;
  -h|--help|"") usage; exit 0 ;;
  *) lg_error "Unknown option: $1"; usage; exit 1 ;;
esac

do_update() {
  lg_require_cmd freshclam "(install the 'clamav' or 'clamav-daemon' package)" || return 1
  lg_info "Updating ClamAV virus definitions..."
  sudo freshclam
  if command -v rkhunter >/dev/null 2>&1; then
    lg_info "Updating rkhunter data files..."
    sudo rkhunter --update
    sudo rkhunter --propupd
  fi
  lg_ok "Definitions updated."
}

do_scan() {
  local target="$1"
  local report_dir="$LG_LOG_DIR/scans"
  mkdir -p "$report_dir"
  local stamp clam_report rk_report
  stamp="$(date '+%Y%m%d-%H%M%S')"
  clam_report="$report_dir/clamscan-$stamp.log"
  rk_report="$report_dir/rkhunter-$stamp.log"

  if lg_require_cmd clamscan "(install the 'clamav' package)"; then
    lg_info "Running ClamAV scan on $target (this can take a while)..."
    clamscan -r --infected --exclude-dir='^/sys|^/proc' "$target" | tee "$clam_report"
    local infected
    infected="$(grep -c "FOUND$" "$clam_report" || true)"
    if [ "${infected:-0}" -gt 0 ]; then
      lg_warn "ClamAV found $infected infected file(s). See $clam_report"
      lg_record_incident "malware" "critical" "ClamAV found $infected infected file(s) under $target"
    else
      lg_ok "ClamAV: no infections found."
    fi
  fi

  if lg_require_cmd rkhunter "(install the 'rkhunter' package)"; then
    lg_info "Running rkhunter rootkit scan..."
    sudo rkhunter --check --sk --report-warnings-only | tee "$rk_report"
    if grep -qi "warning" "$rk_report"; then
      lg_warn "rkhunter reported warnings. See $rk_report"
      lg_record_incident "rootkit" "warning" "rkhunter reported warnings, see $rk_report"
    else
      lg_ok "rkhunter: no warnings."
    fi
  fi
}

case "$MODE" in
  scan) do_scan "$TARGET" ;;
  update) do_update ;;
esac

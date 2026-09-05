#!/usr/bin/env bash
# linux_guardian.sh — ClamAV + rkhunter scan orchestration.
#
# Usage:
#   linux_guardian.sh --scan [PATH]     Quick scan (skips caches/SDKs/git); default PATH=$HOME
#   linux_guardian.sh --scan --full [PATH]
#                                       Scan everything except /sys /proc /dev
#   linux_guardian.sh --scan --changed [PATH]
#                                       Only files newer than the last saved scan
#   linux_guardian.sh --last            Print the last saved scan result (JSON)
#   linux_guardian.sh --update          Update virus/rootkit definitions
#   linux_guardian.sh -h | --help
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"
# shellcheck source=utils.sh
source "$SCRIPT_DIR/utils.sh"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//;1d'; }

MODE=""
TARGET="$HOME"
SCAN_STYLE="quick"
CHANGED=0

if [ $# -eq 0 ]; then
  usage
  exit 0
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --scan) MODE="scan" ;;
    --update) MODE="update" ;;
    --last) MODE="last" ;;
    --full) SCAN_STYLE="full" ;;
    --quick) SCAN_STYLE="quick" ;;
    --changed) CHANGED=1 ;;
    -h|--help) usage; exit 0 ;;
    -*)
      lg_error "Unknown option: $1"
      usage
      exit 1
      ;;
    *)
      if [ "$MODE" = "scan" ]; then
        TARGET="$1"
      else
        lg_error "Unknown argument: $1"
        usage
        exit 1
      fi
      ;;
  esac
  shift
done

if [ -z "$MODE" ]; then
  usage
  exit 0
fi

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

_lg_unbuf() {
  if command -v stdbuf >/dev/null 2>&1; then
    stdbuf -o0 -e0 "$@"
  else
    "$@"
  fi
}

_lg_exclude_regex() {
  if [ "$SCAN_STYLE" = "full" ]; then
    printf '%s' "${LG_CLAM_EXCLUDE_DIRS_FULL}"
  else
    printf '%s' "${LG_CLAM_EXCLUDE_DIRS_QUICK}"
  fi
}

_lg_last_ended_epoch() {
  python3 "$SCRIPT_DIR/scan_store.py" last 2>/dev/null \
    | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    raise SystemExit(1)
print(d.get("ended_epoch") or "")' 2>/dev/null
}

_lg_save_scan() {
  local clam_report="$1" rk_report="$2" target="$3" engine="$4" clam_rc="$5" rk_rc="$6"
  local extra=(--from-log "$clam_report" --target "$target" --mode "$SCAN_STYLE" --engine "$engine" --clam-rc "$clam_rc" --excludes "$(_lg_exclude_regex)")
  [ -n "$rk_report" ] && extra+=(--rk-log "$rk_report")
  [ -n "$rk_rc" ] && extra+=(--rk-rc "$rk_rc")
  [ "$CHANGED" -eq 1 ] && extra+=(--changed-only)
  python3 "$SCRIPT_DIR/scan_store.py" save "${extra[@]}" >/dev/null || lg_warn "Could not persist scan result."
}

_lg_build_changed_list() {
  local target="$1" out="$2" epoch="$3"
  local find_args=("$target" -type f)
  if [ "$SCAN_STYLE" != "full" ]; then
    find_args=(
      "$target"
      \( -path '*/.cache/*' -o -path '*/.git/*' -o -path '*/node_modules/*'
         -o -path '*/.npm/*' -o -path '*/.rustup/*' -o -path '*/.cargo/*'
         -o -path '*/snap/*' -o -path '*/nvidia/nvidia_sdk/*'
         -o -path '*/PX4-Autopilot/*' -o -path '*/STM32Cube/*'
         -o -path '*/st/stm32cubeide/*' -o -path '*/.gz/*'
         -o -path '*/.local/share/Trash/*' \) -prune
      -o -type f -newermt "@${epoch}" -print
    )
  else
    find_args=("$target" -type f -newermt "@${epoch}" -print)
  fi
  find "${find_args[@]}" 2>/dev/null > "$out"
}

do_scan() {
  local target="$1"
  local report_dir="$LG_LOG_DIR/scans"
  mkdir -p "$report_dir"
  local stamp clam_report rk_report
  stamp="$(date '+%Y%m%d-%H%M%S')"
  clam_report="$report_dir/clamscan-$stamp.log"
  rk_report="$report_dir/rkhunter-$stamp.log"

  local exclude
  exclude="$(_lg_exclude_regex)"
  lg_info "Malware/rootkit scan of $target started (${SCAN_STYLE}$([ "$CHANGED" -eq 1 ] && echo ', changed-only'))."
  lg_info "Elapsed time updates every second so you can see it is still running."
  if [ "$SCAN_STYLE" = "quick" ]; then
    lg_info "Quick mode skips caches, git metadata, and bulky SDKs (nvidia/PX4/STM32). Use --full to include them."
  fi
  lg_progress "clamav" "Starting malware/rootkit scan" "step=1" "steps=2" "pct=0"

  local engine="" clam_rc=0 rk_rc="" file_list=""
  if command -v clamdscan >/dev/null 2>&1 && clamdscan --ping >/dev/null 2>&1; then
    engine="clamdscan"
  elif lg_require_cmd clamscan "(install the 'clamav' package)"; then
    engine="clamscan"
    if ! command -v clamdscan >/dev/null 2>&1; then
      lg_info "Tip: install clamav-daemon and run clamd for faster scans (virus DB stays in memory)."
    fi
  fi

  if [ -n "$engine" ]; then
    lg_info "Step 1 of 2 — ClamAV via $engine."
    lg_progress "clamav" "Loading virus signatures" "step=1" "steps=2" "pct=0"

    local file_list=""
    local clam_args=()
    if [ "$engine" = "clamdscan" ]; then
      clam_args=(clamdscan --multiscan --fdpass --infected)
    else
      clam_args=(clamscan -r --infected --stdout --exclude-dir="$exclude")
      if lg_cmd_has_flag clamscan --progress; then
        clam_args+=(--progress)
      fi
    fi

    if [ "$CHANGED" -eq 1 ]; then
      local epoch
      epoch="$(_lg_last_ended_epoch)"
      if [ -z "$epoch" ]; then
        lg_warn "No previous scan result on file; scanning all eligible files instead of --changed."
      else
        file_list="$(mktemp)"
        _lg_build_changed_list "$target" "$file_list" "$epoch"
        local nfiles
        nfiles="$(wc -l < "$file_list" | tr -d ' ')"
        lg_info "Changed-only: $nfiles file(s) newer than the last scan."
        if [ "${nfiles:-0}" -eq 0 ]; then
          lg_ok "Nothing new to scan since the last run."
          printf '----------- SCAN SUMMARY -----------\nScanned files: 0\nInfected files: 0\nTime: 0 sec\nEnd Date: %s\n' \
            "$(date '+%Y:%m:%d %H:%M:%S')" > "$clam_report"
          clam_rc=0
          engine="$engine"
          lg_progress "clamav" "ClamAV finished" "step=1" "steps=2" "pct=100"
        else
          clam_args+=(-f "$file_list")
        fi
      fi
    fi

    if [ ! -s "$clam_report" ] || ! grep -q "SCAN SUMMARY" "$clam_report" 2>/dev/null; then
      if [ -z "$file_list" ]; then
        clam_args+=("$target")
      fi
      _lg_unbuf "${clam_args[@]}" 2>&1 | _lg_unbuf tr '\r' '\n' | _lg_unbuf tee "$clam_report" &
      local clam_pipe_pid=$!
      lg_watch_pid "$clam_pipe_pid" "clamav" "ClamAV scanning $target" "$clam_report" "step=1" "steps=2" || clam_rc=$?
    fi
    [ -n "$file_list" ] && rm -f "$file_list"

    lg_progress "clamav" "ClamAV finished" "step=1" "steps=2" "pct=100"

    local infected
    infected="$(grep -c "FOUND$" "$clam_report" 2>/dev/null || true)"
    if [ "${infected:-0}" -gt 0 ]; then
      lg_warn "ClamAV found $infected infected file(s). See $clam_report"
      lg_record_incident "malware" "critical" "ClamAV found $infected infected file(s) under $target"
    elif [ "$clam_rc" -ne 0 ]; then
      lg_warn "ClamAV exited with status $clam_rc. See $clam_report"
    else
      lg_ok "ClamAV: no infections found."
    fi
  else
    lg_progress "clamav" "ClamAV not installed, skipping" "step=1" "steps=2" "pct=100"
  fi

  if lg_require_cmd rkhunter "(install the 'rkhunter' package)"; then
    lg_info "Step 2 of 2 — rkhunter rootkit scan."
    lg_progress "rkhunter" "Starting rootkit checks" "step=2" "steps=2" "pct=0"

    local rk_cmd=(rkhunter --check --sk --nocolors --no-mail-on-warning)
    if [ "$(id -u)" -ne 0 ]; then
      if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        rk_cmd=(sudo "${rk_cmd[@]}")
      else
        lg_warn "rkhunter is more complete as root. Not prompting for a sudo password (that would look frozen in the GUI)."
        lg_info "Continuing unprivileged. To run the full check: sudo rkhunter --check --sk"
      fi
    fi

    _lg_unbuf "${rk_cmd[@]}" 2>&1 | _lg_unbuf tee "$rk_report" &
    local rk_pipe_pid=$!

    local rk_rc=0
    lg_watch_pid "$rk_pipe_pid" "rkhunter" "rkhunter rootkit checks" "$rk_report" "step=2" "steps=2" || rk_rc=$?

    lg_progress "rkhunter" "rkhunter finished" "step=2" "steps=2" "pct=100"

    if grep -qE '^[[:space:]]*Warning:' "$rk_report" 2>/dev/null \
      || grep -qiE 'one or more warnings' "$rk_report" 2>/dev/null; then
      lg_warn "rkhunter reported warnings. See $rk_report"
      lg_record_incident "rootkit" "warning" "rkhunter reported warnings, see $rk_report"
    elif [ "$rk_rc" -ne 0 ]; then
      lg_warn "rkhunter exited with status $rk_rc. See $rk_report"
    else
      lg_ok "rkhunter: no warnings."
    fi
  else
    lg_progress "rkhunter" "rkhunter not installed, skipping" "step=2" "steps=2" "pct=100"
  fi

  if [ -f "$clam_report" ]; then
    _lg_save_scan "$clam_report" "$rk_report" "$target" "${engine:-clamscan}" "$clam_rc" "${rk_rc:-}"
    lg_info "Scan result saved to $LG_SCAN_DIR/last.json"
  fi
  lg_ok "Malware/rootkit scan complete."
}

do_last() {
  if python3 "$SCRIPT_DIR/scan_store.py" last; then
    return 0
  fi
  if python3 "$SCRIPT_DIR/scan_store.py" import-latest; then
    return 0
  fi
  lg_error "No saved scan result yet. Run --scan first."
  return 1
}

case "$MODE" in
  scan) do_scan "$TARGET" ;;
  update) do_update ;;
  last) do_last ;;
esac

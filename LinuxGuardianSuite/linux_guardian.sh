#!/usr/bin/env bash
# linux_guardian.sh — ClamAV + rkhunter scan orchestration.
#
# Usage:
#   linux_guardian.sh --scan [PATH]     Quick scan (skips caches/SDKs/git); default PATH=$HOME
#   linux_guardian.sh --scan --full [PATH]
#                                       Scan everything except /sys /proc /dev
#   linux_guardian.sh --scan --changed [PATH]
#                                       Only files newer than the last saved scan
#   linux_guardian.sh --scan --rootkit  Also run the rkhunter rootkit check. rkhunter only works as
#                                       root, so this asks for your password through the desktop's
#                                       own prompt (pkexec). Without it the rootkit check is skipped
#                                       and the result says so.
#   linux_guardian.sh --last            Print the last saved scan result (JSON)
#   linux_guardian.sh --health          How much to trust a scan right now: virus-definition age,
#                                       automatic-update state, rootkit baseline (no root needed)
#   linux_guardian.sh --update          Update ClamAV virus definitions (freshclam, via pkexec).
#                                       Never touches rkhunter's baseline: refreshing that tells
#                                       rkhunter "the system as it is now is the good one", so it's
#                                       a manual decision (sudo rkhunter --propupd).
#   linux_guardian.sh --enable-auto-update
#                                       Turn on ClamAV's background updater (systemctl enable --now
#                                       clamav-freshclam, via pkexec). It is a standing change to the
#                                       system, so the app asks first and this only does that one thing.
#   linux_guardian.sh -h | --help
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"
# shellcheck source=utils.sh
source "$SCRIPT_DIR/utils.sh"

usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

# What runs as root. FIXED text: no variables, no data, nothing spliced in, so what
# gets root is exactly what is written here (tests/test_guardian_privileged.sh checks).
PRIV_SCRIPT_FRESHCLAM='echo "Running freshclam as root..."; exec freshclam'
PRIV_SCRIPT_ENABLE_FRESHCLAM='exec systemctl enable --now clamav-freshclam'
PRIV_SCRIPT_RKHUNTER='exec rkhunter --check --sk --nocolors --no-mail-on-warning'

MODE=""
TARGET="$HOME"
SCAN_STYLE="quick"
CHANGED=0
ROOTKIT=0

if [ $# -eq 0 ]; then
  usage
  exit 0
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --scan) MODE="scan" ;;
    --update) MODE="update" ;;
    --last) MODE="last" ;;
    --health) MODE="health" ;;
    --enable-auto-update) MODE="enable_auto_update" ;;
    --rootkit) ROOTKIT=1 ;;
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
  lg_info "Updating ClamAV virus definitions (the desktop will ask for your password)..."
  lg_progress "update" "Updating virus definitions" "step=1" "steps=1" "pct=0"
  mkdir -p "$LG_LOG_DIR"
  local log rcfile rc
  log="$LG_LOG_DIR/freshclam-$(date '+%Y%m%d-%H%M%S').log"
  rcfile="$(mktemp)"
  # lg_tee_log keeps draining even if the reader goes away, so closing the GUI can't SIGPIPE freshclam mid-download.
  { lg_run_privileged "$PRIV_SCRIPT_FRESHCLAM"; echo $? > "$rcfile"; } 2>&1 | lg_tee_log "$log"
  rc="$(cat "$rcfile" 2>/dev/null)"; rm -f "$rcfile"
  rc="${rc:-1}"
  lg_progress "update" "Definitions update finished" "step=1" "steps=1" "pct=100"
  case "$rc" in
    0) lg_ok "Virus definitions are up to date." ;;
    126|127)
      lg_warn "Cancelled: the password prompt was dismissed (or couldn't be shown). Nothing was changed."
      return 2
      ;;
    *)
      if grep -qi 'locked' "$log" 2>/dev/null; then
        lg_warn "freshclam is already running (the automatic updater is probably mid-update). Try again in a minute."
      else
        lg_error "freshclam failed (exit $rc). See $log"
      fi
      return 1
      ;;
  esac
}

do_enable_auto_update() {
  if ! systemctl cat clamav-freshclam >/dev/null 2>&1; then
    lg_error "The ClamAV updater service (clamav-freshclam) is not installed. Install it with: sudo apt install clamav-freshclam"
    return 1
  fi
  lg_info "Turning on ClamAV's automatic definition updates (the desktop will ask for your password)..."
  local rcfile rc
  rcfile="$(mktemp)"
  { lg_run_privileged "$PRIV_SCRIPT_ENABLE_FRESHCLAM"; echo $? > "$rcfile"; } 2>&1 | lg_tee_log "$LG_LOG_DIR/enable-auto-update.log"
  rc="$(cat "$rcfile" 2>/dev/null)"; rm -f "$rcfile"
  case "${rc:-1}" in
    0) lg_ok "Automatic updates are on: definitions now refresh in the background, and after every reboot." ;;
    126|127)
      lg_warn "Cancelled: the password prompt was dismissed. Nothing was changed."
      return 2
      ;;
    *) lg_error "Could not enable the updater (exit ${rc:-1}). See $LG_LOG_DIR/enable-auto-update.log"; return 1 ;;
  esac
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
  local clam_report="$1" rk_report="$2" target="$3" engine="$4" clam_rc="$5" rk_rc="$6" rk_status="${7:-}"
  local extra=(--from-log "$clam_report" --target "$target" --mode "$SCAN_STYLE" --engine "$engine" --clam-rc "$clam_rc" --excludes "$(_lg_exclude_regex)")
  [ -n "$rk_report" ] && extra+=(--rk-log "$rk_report")
  [ -n "$rk_rc" ] && extra+=(--rk-rc "$rk_rc")
  [ -n "$rk_status" ] && extra+=(--rk-status "$rk_status")
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

  local rk_status="" rk_rc=""
  if lg_require_cmd rkhunter "(install the 'rkhunter' package)"; then
    lg_info "Step 2 of 2 — rkhunter rootkit scan."
    lg_progress "rkhunter" "Starting rootkit checks" "step=2" "steps=2" "pct=0"

    if [ "$(id -u)" -ne 0 ] && { [ "$ROOTKIT" -ne 1 ] || ! command -v pkexec >/dev/null 2>&1; }; then
      # rkhunter refuses to run unprivileged. Never ask for a password unless the user opted in.
      rk_status="needs_root"
      rk_report=""
      if [ "$ROOTKIT" -eq 1 ]; then
        lg_warn "No way to ask for a password here (pkexec is not installed); the rootkit check was skipped."
      else
        lg_warn "Rootkit check skipped: rkhunter can only run as root. Re-run with --rootkit (or tick the box in the app) to approve it with your password."
      fi
      lg_warn "This result covers malware only (ClamAV)."
      lg_progress "rkhunter" "Rootkit check skipped (needs root)" "step=2" "steps=2" "pct=100"
    else
      lg_info "rkhunter needs root: approve the password prompt if one appears. The prompt belongs to your desktop; this app never sees the password."
      local rk_rcfile
      rk_rcfile="$(mktemp)"
      { lg_run_privileged "$PRIV_SCRIPT_RKHUNTER"; echo $? > "$rk_rcfile"; } 2>&1 | lg_tee_log "$rk_report" &
      local rk_pipe_pid=$!
      lg_watch_pid "$rk_pipe_pid" "rkhunter" "rkhunter rootkit checks (approve the password prompt if shown)" "$rk_report" "step=2" "steps=2" || true
      rk_rc="$(cat "$rk_rcfile" 2>/dev/null)"; rm -f "$rk_rcfile"
      rk_rc="${rk_rc:-1}"
      lg_progress "rkhunter" "rkhunter finished" "step=2" "steps=2" "pct=100"

      if [ "$rk_rc" = "126" ] || [ "$rk_rc" = "127" ]; then
        rk_status="cancelled"
        lg_warn "Rootkit check cancelled: the password prompt was dismissed. Nothing was run."
      else
        local rk_total rk_changed
        rk_total="$(grep -cE '^[[:space:]]*Warning:' "$rk_report" 2>/dev/null || true)"
        rk_changed="$(grep -ciE '^[[:space:]]*Warning: The file properties have changed' "$rk_report" 2>/dev/null || true)"
        if [ "${rk_total:-0}" -gt 0 ] || grep -qiE 'one or more warnings' "$rk_report" 2>/dev/null; then
          lg_warn "rkhunter reported ${rk_total:-some} warning(s). See $rk_report"
          lg_record_incident "rootkit" "warning" "rkhunter reported warnings, see $rk_report"
          if [ "${rk_changed:-0}" -gt 0 ]; then
            lg_info "${rk_changed} of them are 'file properties have changed': usually just package updates, because rkhunter's baseline is not refreshed automatically here."
            lg_info "Look at the other warnings first. If you trust this system, you can refresh the baseline yourself: sudo rkhunter --propupd (this app never does it for you)."
          fi
        elif [ "$rk_rc" -ne 0 ]; then
          lg_warn "rkhunter exited with status $rk_rc. See $rk_report"
        else
          lg_ok "rkhunter: no warnings."
        fi
      fi
    fi
  else
    lg_progress "rkhunter" "rkhunter not installed, skipping" "step=2" "steps=2" "pct=100"
  fi

  if [ -f "$clam_report" ]; then
    _lg_save_scan "$clam_report" "$rk_report" "$target" "${engine:-clamscan}" "$clam_rc" "${rk_rc:-}" "${rk_status:-}"
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
  enable_auto_update) do_enable_auto_update ;;
  health) python3 "$SCRIPT_DIR/scanner_health.py" --text ;;
  last) do_last ;;
esac

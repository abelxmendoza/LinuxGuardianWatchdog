#!/usr/bin/env bash
# linux_watchdog.sh — SHA-256 file integrity baseline + honeypot monitor.
#
# Usage:
#   linux_watchdog.sh --init              Create/refresh the baseline
#   linux_watchdog.sh --check             Compare current state to baseline
#   linux_watchdog.sh --resume            Resume an interrupted --init/--check
#   linux_watchdog.sh -h | --help
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"
# shellcheck source=utils.sh
source "$SCRIPT_DIR/utils.sh"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//;1d'; }

MODE=""
case "${1:-}" in
  --init) MODE="init" ;;
  --check) MODE="check" ;;
  --resume) MODE="resume" ;;
  -h|--help|"") usage; exit 0 ;;
  *) lg_error "Unknown option: $1"; usage; exit 1 ;;
esac

BASELINE_FILE="$LG_BASELINE_DIR/documents.sha256"
CHECKPOINT_FILE="$LG_CHECKPOINT_DIR/watchdog.checkpoint"

ensure_honeypot() {
  if [ ! -d "$LG_HONEYPOT_DIR" ]; then
    mkdir -p "$LG_HONEYPOT_DIR"
    cat > "$LG_HONEYPOT_DIR/passwords.txt" <<'EOF'
This is a decoy file created by LinuxGuardian Watchdog.
If you did not create this file and did not expect to see it opened,
something on this machine accessed it without authorization.
EOF
    lg_info "Honeypot created at $LG_HONEYPOT_DIR"
  fi
}

honeypot_atime() {
  stat -c '%X' "$LG_HONEYPOT_DIR/passwords.txt" 2>/dev/null || echo 0
}

# Starts a parallel hash of $LG_MONITORED_DIRS_DEFAULT into $1. Sets HASH_PID.
# Must not run in command substitution — the background job has to stay in this shell.
_hash_monitored() {
  local outfile="$1"
  find $LG_MONITORED_DIRS_DEFAULT -type f 2>/dev/null \
    | xargs -P "$(nproc 2>/dev/null || echo 2)" -I{} sha256sum "{}" 2>/dev/null \
    > "$outfile" &
  HASH_PID=$!
}

_watch_hash() {
  local pid="$1" outfile="$2" total="$3" verb="$4"
  local start elapsed done pct eta
  start="$(date +%s)"
  while kill -0 "$pid" 2>/dev/null; do
    elapsed=$(( $(date +%s) - start ))
    done="$(wc -l < "$outfile" 2>/dev/null || echo 0)"
    done="${done// /}"
    [[ "$done" =~ ^[0-9]+$ ]] || done=0
    pct=""
    eta=""
    if [[ "$total" =~ ^[0-9]+$ ]] && [ "$total" -gt 0 ]; then
      pct=$((done * 100 / total))
      [ "$pct" -gt 99 ] && pct=99
      if [ "$done" -gt 0 ] && [ "$elapsed" -gt 0 ] && [ "$done" -lt "$total" ]; then
        eta=$((elapsed * (total - done) / done))
      fi
    fi
    local extras=("done=$done" "elapsed_sec=$elapsed")
    [ -n "$total" ] && extras+=("total=$total")
    [ -n "$pct" ] && extras+=("pct=$pct")
    [ -n "$eta" ] && extras+=("eta_sec=$eta")
    lg_progress "integrity" "$verb $done${total:+ of $total} files ($(lg_fmt_duration "$elapsed") elapsed)" "${extras[@]}"
    sleep 1
  done
  wait "$pid" 2>/dev/null
}

do_init() {
  ensure_honeypot
  lg_info "Building integrity baseline for: $LG_MONITORED_DIRS_DEFAULT"
  : > "$CHECKPOINT_FILE"
  local total
  total="$(find $LG_MONITORED_DIRS_DEFAULT -type f 2>/dev/null | wc -l)"
  total="${total// /}"
  lg_info "Hashing ${total} files (progress updates every second)..."
  lg_progress "integrity" "Hashing files for baseline" "pct=0" "done=0" "total=$total"
  : > "$BASELINE_FILE"
  local hash_pid
  _hash_monitored "$BASELINE_FILE"
  hash_pid="$HASH_PID"
  _watch_hash "$hash_pid" "$BASELINE_FILE" "$total" "Hashed"
  cp "$BASELINE_FILE" "$CHECKPOINT_FILE"
  honeypot_atime > "$LG_BASELINE_DIR/honeypot.atime"
  rm -f "$CHECKPOINT_FILE"
  lg_progress "integrity" "Baseline complete" "pct=100" "done=$total" "total=$total"
  lg_ok "Baseline written to $BASELINE_FILE ($(wc -l < "$BASELINE_FILE") files)"
}

do_check() {
  if [ ! -f "$BASELINE_FILE" ]; then
    lg_error "No baseline found. Run with --init first."
    exit 1
  fi
  ensure_honeypot
  lg_info "Checking current state against baseline..."
  local total
  total="$(wc -l < "$BASELINE_FILE")"
  total="${total// /}"
  lg_info "Hashing files to compare against $total baseline entries (progress updates every second)..."
  lg_progress "integrity" "Hashing files for comparison" "pct=0" "done=0" "total=$total"

  local tmp_current hash_pid
  tmp_current="$(mktemp)"
  : > "$tmp_current"
  _hash_monitored "$tmp_current"
  hash_pid="$HASH_PID"
  _watch_hash "$hash_pid" "$tmp_current" "$total" "Hashed"
  lg_progress "integrity" "Comparing hashes" "pct=99" "done=$total" "total=$total"

  local changed
  changed="$(comm -13 <(sort "$BASELINE_FILE") <(sort "$tmp_current") | awk '{print $2}')"
  local missing
  missing="$(comm -23 <(sort "$BASELINE_FILE") <(sort "$tmp_current") | awk '{print $2}')"
  rm -f "$tmp_current"

  local any=0
  if [ -n "$changed" ]; then
    any=1
    lg_warn "Modified or new files detected:"
    echo "$changed" | while read -r f; do
      echo "    $f"
      lg_record_incident "integrity" "warning" "File changed: $f"
    done
  fi
  if [ -n "$missing" ]; then
    any=1
    lg_warn "Missing files (present in baseline, gone now):"
    echo "$missing" | while read -r f; do
      echo "    $f"
      lg_record_incident "integrity" "warning" "File missing: $f"
    done
  fi

  local baseline_atime current_atime
  baseline_atime="$(cat "$LG_BASELINE_DIR/honeypot.atime" 2>/dev/null || echo 0)"
  current_atime="$(honeypot_atime)"
  if [ "$current_atime" != "$baseline_atime" ]; then
    any=1
    lg_warn "Honeypot file was accessed — possible unauthorized read of $LG_HONEYPOT_DIR"
    lg_record_incident "honeypot" "critical" "Honeypot accessed at $LG_HONEYPOT_DIR"
  fi

  if [ "$any" -eq 0 ]; then
    lg_ok "No changes detected. Integrity intact."
  fi
  lg_progress "integrity" "Integrity check complete" "pct=100" "total=$total"
}

case "$MODE" in
  init) do_init ;;
  check) do_check ;;
  resume)
    lg_info "Resuming from checkpoint (if any)..."
    do_init
    ;;
esac

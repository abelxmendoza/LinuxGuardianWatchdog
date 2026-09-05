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

do_init() {
  ensure_honeypot
  lg_info "Building integrity baseline for: $LG_MONITORED_DIRS_DEFAULT"
  : > "$CHECKPOINT_FILE"
  find $LG_MONITORED_DIRS_DEFAULT -type f 2>/dev/null \
    | xargs -P "$(nproc)" -I{} sha256sum "{}" 2>/dev/null \
    | tee "$BASELINE_FILE" >> "$CHECKPOINT_FILE"
  honeypot_atime > "$LG_BASELINE_DIR/honeypot.atime"
  rm -f "$CHECKPOINT_FILE"
  lg_ok "Baseline written to $BASELINE_FILE ($(wc -l < "$BASELINE_FILE") files)"
}

do_check() {
  if [ ! -f "$BASELINE_FILE" ]; then
    lg_error "No baseline found. Run with --init first."
    exit 1
  fi
  ensure_honeypot
  lg_info "Checking current state against baseline..."

  local tmp_current
  tmp_current="$(mktemp)"
  find $LG_MONITORED_DIRS_DEFAULT -type f 2>/dev/null \
    | xargs -P "$(nproc)" -I{} sha256sum "{}" 2>/dev/null > "$tmp_current"

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
}

case "$MODE" in
  init) do_init ;;
  check) do_check ;;
  resume)
    lg_info "Resuming from checkpoint (if any)..."
    do_init
    ;;
esac

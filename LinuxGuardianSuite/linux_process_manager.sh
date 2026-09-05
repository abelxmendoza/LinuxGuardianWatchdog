#!/usr/bin/env bash
# linux_process_manager.sh — the "process killer": list and terminate processes.
#
# Usage:
#   linux_process_manager.sh --list [--sort cpu|mem]
#   linux_process_manager.sh --kill PID [--force]
#   linux_process_manager.sh --kill-name NAME [--force]
#   linux_process_manager.sh -h | --help
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"
# shellcheck source=utils.sh
source "$SCRIPT_DIR/utils.sh"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//;1d'; }

MODE="" TARGET="" SORT="cpu" FORCE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --list) MODE="list" ;;
    --sort) SORT="${2:-cpu}"; shift ;;
    --kill) MODE="kill"; TARGET="${2:-}"; shift ;;
    --kill-name) MODE="kill-name"; TARGET="${2:-}"; shift ;;
    --force) FORCE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) lg_error "Unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done

do_list() {
  local sort_col="-%cpu"
  [ "$SORT" = "mem" ] && sort_col="-%mem"
  ps -eo pid,ppid,%cpu,%mem,etimes,user,comm --sort="$sort_col" --no-headers
}

do_kill() {
  local pid="$1"
  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
    lg_error "No such process: $pid"
    return 1
  fi
  local sig="TERM"
  [ "$FORCE" -eq 1 ] && sig="KILL"
  if kill "-$sig" "$pid" 2>/dev/null; then
    lg_ok "Sent SIG$sig to PID $pid"
    lg_record_incident "process" "info" "Killed PID $pid with SIG$sig"
  else
    lg_error "Failed to signal PID $pid (owned by another user? try with sudo)"
    return 1
  fi
}

do_kill_name() {
  local name="$1"
  local self_pid=$$
  local pids
  pids="$(pgrep -f "$name" | grep -vx "$self_pid" || true)"
  if [ -z "$pids" ]; then
    lg_warn "No running process matches '$name'"
    return 0
  fi
  local sig="TERM"
  [ "$FORCE" -eq 1 ] && sig="KILL"
  echo "$pids" | while read -r pid; do
    [ -z "$pid" ] && continue
    if kill "-$sig" "$pid" 2>/dev/null; then
      lg_ok "Sent SIG$sig to PID $pid ($name)"
      lg_record_incident "process" "info" "Killed PID $pid ($name) with SIG$sig"
    else
      lg_error "Failed to signal PID $pid ($name)"
    fi
  done
}

case "$MODE" in
  list) do_list ;;
  kill) do_kill "$TARGET" ;;
  kill-name) do_kill_name "$TARGET" ;;
  "") usage; exit 0 ;;
esac

#!/usr/bin/env bash
# linux_watchdog.sh — SHA-256 file integrity baseline + honeypot monitor.
#
# Watches ~/Documents plus the places malware hides or restarts from (shell start-up files, ~/.ssh,
# autostart entries, user services, /etc/ld.so.preload, /etc/passwd...). Skips caches, .git internals
# and the honeypot itself. The work is done by integrity.py.
#
# Usage:
#   linux_watchdog.sh --init              Create/refresh the baseline (accepts the current state as good)
#   linux_watchdog.sh --check             Compare current state to the baseline
#   linux_watchdog.sh --status            Baseline age and size (JSON)
#   linux_watchdog.sh --roots             List the locations being watched
#   linux_watchdog.sh --resume            Same as --init (kept for older callers)
#   linux_watchdog.sh -h | --help
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"
# shellcheck source=utils.sh
source "$SCRIPT_DIR/utils.sh"

usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

export LG_HOME LG_HONEYPOT_DIR

case "${1:-}" in
  --init|--resume) exec python3 "$SCRIPT_DIR/integrity.py" --init ;;
  --check) exec python3 "$SCRIPT_DIR/integrity.py" --check ;;
  --status) exec python3 "$SCRIPT_DIR/integrity.py" --status ;;
  --roots) exec python3 "$SCRIPT_DIR/integrity.py" --roots ;;
  -h|--help|"") usage; exit 0 ;;
  *) lg_error "Unknown option: $1"; usage; exit 1 ;;
esac

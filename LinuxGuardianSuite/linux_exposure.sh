#!/usr/bin/env bash
# linux_exposure.sh — what is listening on this machine, and who can reach it.
#
# Usage:
#   linux_exposure.sh --check [--json]   Report (human-readable; --json for the GUI)
#   linux_exposure.sh --summary          One line of counts
#   linux_exposure.sh --record           Report, and log a security event for each NEW
#                                        or CHANGED exposure (quiet if nothing changed)
#   linux_exposure.sh -h | --help
#
# DETECTION ONLY. This never closes a port, stops a service, or changes the
# firewall, and it needs no root. Where that limits what it can see (process
# names for root-owned listeners; firewall allow-rules) it says so instead of
# guessing. Any advice it prints is text for you to act on.
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"
# shellcheck source=utils.sh
source "$SCRIPT_DIR/utils.sh"

INVENTORY="$SCRIPT_DIR/exposure_inventory.py"

# Print only the leading comment block.
usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

if [ $# -eq 0 ]; then
  usage
  exit 0
fi

MODE="" JSON=0
while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE="check" ;;
    --summary) MODE="summary" ;;
    --record) MODE="record" ;;
    --json) JSON=1 ;;
    -h|--help) usage; exit 0 ;;
    *) lg_error "Unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done

if [ -z "$MODE" ]; then
  usage
  exit 0
fi

if ! command -v ss >/dev/null 2>&1; then
  lg_error "'ss' (iproute2) is required to list listening sockets and wasn't found."
  exit 1
fi

args=()
[ "$JSON" -eq 0 ] && args+=(--text)

case "$MODE" in
  check) python3 "$INVENTORY" ${args[@]+"${args[@]}"} ;;
  summary) python3 "$INVENTORY" --summary ;;
  record) python3 "$INVENTORY" --record ${args[@]+"${args[@]}"} ;;
esac

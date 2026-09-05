#!/usr/bin/env bash
# linux_cache_cleanup.sh — reports and (optionally) clears browser + system caches.
#
# Usage:
#   linux_cache_cleanup.sh --scan             Show reclaimable cache sizes (default, safe)
#   linux_cache_cleanup.sh --clean --apply    Actually delete cache contents
#   linux_cache_cleanup.sh -h | --help
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"
# shellcheck source=utils.sh
source "$SCRIPT_DIR/utils.sh"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//;1d'; }

MODE="scan" APPLY=0
for arg in "$@"; do
  case "$arg" in
    --scan) MODE="scan" ;;
    --clean) MODE="clean" ;;
    --apply) APPLY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) lg_error "Unknown option: $arg"; usage; exit 1 ;;
  esac
done

# path-glob:human-label pairs. Globs are expanded at use time.
CACHE_TARGETS=(
  "$HOME/.cache/*:User cache (~/.cache/*)"
  "$HOME/.mozilla/firefox/*/cache2:Firefox cache"
  "$HOME/.cache/google-chrome/*/Cache:Google Chrome cache"
  "$HOME/.cache/chromium/*/Cache:Chromium cache"
  "$HOME/.cache/BraveSoftware/*/Cache:Brave cache"
  "$HOME/.thumbnails:Thumbnail cache"
)

human() { numfmt --to=iec --suffix=B "$1" 2>/dev/null || echo "${1} B"; }

do_scan() {
  local total=0 size expanded path label
  for entry in "${CACHE_TARGETS[@]}"; do
    path="${entry%%:*}"; label="${entry#*:}"
    for expanded in $path; do
      [ -e "$expanded" ] || continue
      size="$(du -sb "$expanded" 2>/dev/null | awk '{print $1}')"
      [ -z "$size" ] && continue
      total=$((total + size))
      printf "%10s  %-28s %s\n" "$(human "$size")" "$label" "$expanded"
    done
  done
  echo "----------------------------------------"
  echo "Total reclaimable: $(human "$total")"
}

do_clean() {
  if [ "$APPLY" -ne 1 ]; then
    lg_warn "Dry run (default). Nothing deleted — re-run with --clean --apply to actually clear caches."
    do_scan
    return 0
  fi
  local expanded path label freed=0 size
  for entry in "${CACHE_TARGETS[@]}"; do
    path="${entry%%:*}"; label="${entry#*:}"
    for expanded in $path; do
      [ -e "$expanded" ] || continue
      size="$(du -sb "$expanded" 2>/dev/null | awk '{print $1}')"
      lg_info "Clearing $label ($expanded)..."
      find "$expanded" -mindepth 1 -delete 2>/dev/null
      freed=$((freed + ${size:-0}))
    done
  done
  lg_ok "Cache cleanup complete. Freed approximately $(human "$freed")."
  lg_record_incident "maintenance" "info" "Cache cleanup freed approximately $(human "$freed")"
}

case "$MODE" in
  scan) do_scan ;;
  clean) do_clean ;;
esac

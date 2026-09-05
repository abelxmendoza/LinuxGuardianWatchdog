#!/usr/bin/env bash
# linux_cache_cleanup.sh — reports and (optionally) clears browser + system
# caches, grouped into categories so a caller can clear just some of them.
#
# Usage:
#   linux_cache_cleanup.sh --scan                         Preview sizes (default, safe)
#   linux_cache_cleanup.sh --clean --apply [--only CATS]  Actually delete
#                                                          (CATS: comma-separated
#                                                          category ids; omit for all)
#   linux_cache_cleanup.sh -h | --help
#
# --scan prints pipe-delimited lines: category|bytes|human|path
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"
# shellcheck source=utils.sh
source "$SCRIPT_DIR/utils.sh"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//;1d'; }

MODE="scan" APPLY=0 ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --scan) MODE="scan" ;;
    --clean) MODE="clean" ;;
    --apply) APPLY=1 ;;
    --only) ONLY="${2:-}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) lg_error "Unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done

human() { numfmt --to=iec --suffix=B "$1" 2>/dev/null || echo "${1} B"; }

BROWSER_PATTERNS=(
  "$HOME/.mozilla/firefox/*/cache2"
  "$HOME/.cache/google-chrome/*/Cache"
  "$HOME/.cache/chromium/*/Cache"
  "$HOME/.cache/BraveSoftware/*/Cache"
)
THUMBNAIL_PATTERNS=(
  "$HOME/.cache/thumbnails"
  "$HOME/.thumbnails"
)

collect() {
  local category="$1"; shift
  local pattern expanded size
  for pattern in "$@"; do
    for expanded in $pattern; do
      [ -e "$expanded" ] || continue
      size="$(du -sb "$expanded" 2>/dev/null | awk '{print $1}')"
      [ -z "$size" ] && continue
      printf '%s|%s|%s\n' "$category" "$size" "$expanded"
    done
  done
}

collect_app_cache() {
  # Everything directly under ~/.cache/* not already counted as a browser
  # or thumbnail cache above (avoids double-counting).
  [ -d "$HOME/.cache" ] || return 0
  local dir base size
  for dir in "$HOME"/.cache/*/; do
    [ -d "$dir" ] || continue
    base="$(basename "$dir")"
    case "$base" in
      google-chrome|chromium|BraveSoftware|thumbnails) continue ;;
    esac
    size="$(du -sb "$dir" 2>/dev/null | awk '{print $1}')"
    [ -z "$size" ] && continue
    printf 'app_cache|%s|%s\n' "$size" "${dir%/}"
  done
}

all_entries() {
  collect browser "${BROWSER_PATTERNS[@]}"
  collect thumbnails "${THUMBNAIL_PATTERNS[@]}"
  collect_app_cache
}

category_selected() {
  local cat="$1"
  [ -z "$ONLY" ] && return 0
  case ",$ONLY," in *",$cat,"*) return 0 ;; esac
  return 1
}

do_scan() {
  local category size path
  while IFS='|' read -r category size path; do
    printf '%s|%s|%s|%s\n' "$category" "$size" "$(human "$size")" "$path"
  done < <(all_entries)
}

do_clean() {
  if [ "$APPLY" -ne 1 ]; then
    lg_warn "Dry run (default). Nothing deleted — re-run with --clean --apply to actually clear caches."
    do_scan
    return 0
  fi
  local category size path freed=0
  while IFS='|' read -r category size path; do
    category_selected "$category" || continue
    lg_info "Clearing $path ($category)..."
    find "$path" -mindepth 1 -delete 2>/dev/null
    freed=$((freed + size))
  done < <(all_entries)
  lg_ok "Cache cleanup complete. Freed approximately $(human "$freed")."
  lg_record_incident "maintenance" "info" "Cache cleanup freed approximately $(human "$freed")"
}

case "$MODE" in
  scan) do_scan ;;
  clean) do_clean ;;
esac

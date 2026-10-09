#!/usr/bin/env bash
# linux_apps.sh — move your apps to another laptop running the same Ubuntu.
#
# Usage:
#   linux_apps.sh --export [FILE]       List this laptop's apps into a file (no files, passwords or keys)
#   linux_apps.sh --plan FILE           Preview what importing FILE here would do (changes nothing)
#   linux_apps.sh --install FILE        Install the Ubuntu apps and snaps from FILE that are available
#                                       here (password via the desktop prompt)
#       --include-classic               Also install classic snaps (they run unconfined)
#       --apt-only | --snaps-only       Only one kind
#   linux_apps.sh -h | --help
#
# Never adds a repository or signing key, never removes anything, skips hardware-specific packages,
# and refuses if the Ubuntu release or CPU architecture differs. Exit: 0 ok, 1 error, 2 cancelled, 3 blocked.
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"
# shellcheck source=utils.sh
source "$SCRIPT_DIR/utils.sh"

usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

# What runs as root. FIXED text: package names arrive only as "$@" and are re-validated here as root.
# No --allow-*, no repository or key handling, and --no-remove so a conflict fails instead of removing anything.
PRIV_SCRIPT_APT_INSTALL='
if [ "$#" -eq 0 ]; then echo "no packages given" >&2; exit 2; fi
for p in "$@"; do
  case "$p" in
    ""|-*|*[!a-z0-9+.:-]*) echo "refusing invalid package name" >&2; exit 2 ;;
  esac
done
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || exit 1
exec apt-get install -y --no-remove -- "$@"
'
PRIV_SCRIPT_SNAP_INSTALL='
if [ "$#" -eq 0 ]; then echo "no snaps given" >&2; exit 2; fi
for p in "$@"; do
  case "$p" in
    ""|-*|*[!a-z0-9-]*) echo "refusing invalid snap name" >&2; exit 2 ;;
  esac
done
rc=0
for p in "$@"; do snap install "$p" || rc=1; done
exit $rc
'
PRIV_SCRIPT_SNAP_CLASSIC='
if [ "$#" -eq 0 ]; then echo "no snaps given" >&2; exit 2; fi
for p in "$@"; do
  case "$p" in
    ""|-*|*[!a-z0-9-]*) echo "refusing invalid snap name" >&2; exit 2 ;;
  esac
done
rc=0
for p in "$@"; do snap install --classic "$p" || rc=1; done
exit $rc
'

MODE="" FILE="" CLASSIC=0 WANT_APT=1 WANT_SNAP=1
case "${1:-}" in
  --export) MODE="export"; FILE="${2:-}" ;;
  --plan) MODE=plan; FILE="${2:-}" ;;
  --install) MODE=install; FILE="${2:-}"; shift 2 || true
    while [ $# -gt 0 ]; do
      case "$1" in
        --include-classic) CLASSIC=1 ;;
        --apt-only) WANT_SNAP=0 ;;
        --snaps-only) WANT_APT=0 ;;
        *) lg_error "Unknown option: $1"; exit 1 ;;
      esac
      shift
    done ;;
  -h|--help|"") usage; exit 0 ;;
  *) lg_error "Unknown option: $1"; usage; exit 1 ;;
esac

MANIFEST="$SCRIPT_DIR/app_manifest.py"

do_export() {
  if [ -n "$FILE" ]; then python3 "$MANIFEST" --export "$FILE"; else python3 "$MANIFEST" --export; fi
}

do_plan() {
  [ -n "$FILE" ] || { lg_error "Give the app list file."; return 1; }
  python3 "$MANIFEST" --plan "$FILE"
}

# Names for one kind, from the plan computed on THIS machine (never straight from the file).
_names() { python3 "$MANIFEST" --names "$FILE" --kind "$1"; }

_run_root() {   # _run_root LOGNAME SCRIPT NAME...
  local logname="$1" script="$2"; shift 2
  local log_dir="$LG_LOG_DIR/apps" log rc
  mkdir -p "$log_dir"
  log="$log_dir/$logname-$(date '+%Y%m%d-%H%M%S').log"
  trap '' PIPE
  lg_run_privileged "$script" "$@" 2>&1 | lg_tee_log "$log"
  rc=${PIPESTATUS[0]}
  return "$rc"
}

_check_names() {   # second line of defence: nothing odd goes to root
  local re="$1"; shift
  local n
  for n in "$@"; do
    [[ "$n" =~ $re ]] || { lg_error "Refusing to pass an invalid name to root: $n"; return 1; }
  done
}

do_install() {
  [ -n "$FILE" ] || { lg_error "Give the app list file."; return 1; }
  local plan_out
  if ! plan_out="$(python3 "$MANIFEST" --plan "$FILE" 2>&1)"; then
    lg_error "$plan_out"
    return 3
  fi
  printf '%s\n' "$plan_out"

  # The same release guard as the Updates tab: never install onto a system whose sources point at another release.
  if ! python3 "$SCRIPT_DIR/update_inventory.py" --guard; then
    lg_error "Blocked by the release guard. Nothing was installed."
    return 3
  fi

  local apt_names=() snap_names=() classic_names=() line failed=0 cancelled=0
  if [ "$WANT_APT" -eq 1 ]; then
    while IFS= read -r line; do [ -n "$line" ] && apt_names+=("$line"); done < <(_names apt)
  fi
  if [ "$WANT_SNAP" -eq 1 ]; then
    while IFS= read -r line; do [ -n "$line" ] && snap_names+=("$line"); done < <(_names snap)
    if [ "$CLASSIC" -eq 1 ]; then
      while IFS= read -r line; do [ -n "$line" ] && classic_names+=("$line"); done < <(_names snap-classic)
    fi
  fi
  if [ $(( ${#apt_names[@]} + ${#snap_names[@]} + ${#classic_names[@]} )) -eq 0 ]; then
    lg_ok "Nothing to install: everything installable is already here."
    return 0
  fi
  _check_names '^[a-z0-9][a-z0-9+.:-]*$' ${apt_names[@]+"${apt_names[@]}"} || return 1
  _check_names '^[a-z0-9][a-z0-9-]*$' ${snap_names[@]+"${snap_names[@]}"} ${classic_names[@]+"${classic_names[@]}"} || return 1

  lg_info "Installing ${#apt_names[@]} Ubuntu apps, ${#snap_names[@]} snaps, ${#classic_names[@]} classic snaps. A password prompt will appear."
  local rc
  if [ "${#apt_names[@]}" -gt 0 ]; then
    _run_root apt "$PRIV_SCRIPT_APT_INSTALL" "${apt_names[@]}"; rc=$?
    case "$rc" in
      0) lg_ok "Installed ${#apt_names[@]} Ubuntu apps." ;;
      126|127) cancelled=1 ;;
      *) lg_error "apt could not install them (it never removes anything, so a conflict stops it). See $LG_LOG_DIR/apps"; failed=1 ;;
    esac
  fi
  if [ "$cancelled" -eq 0 ] && [ "${#snap_names[@]}" -gt 0 ]; then
    _run_root snap "$PRIV_SCRIPT_SNAP_INSTALL" "${snap_names[@]}"; rc=$?
    case "$rc" in
      0) lg_ok "Installed ${#snap_names[@]} snaps." ;;
      126|127) cancelled=1 ;;
      *) lg_error "Some snaps failed. See $LG_LOG_DIR/apps"; failed=1 ;;
    esac
  fi
  if [ "$cancelled" -eq 0 ] && [ "${#classic_names[@]}" -gt 0 ]; then
    _run_root snap-classic "$PRIV_SCRIPT_SNAP_CLASSIC" "${classic_names[@]}"; rc=$?
    case "$rc" in
      0) lg_ok "Installed ${#classic_names[@]} classic snaps." ;;
      126|127) cancelled=1 ;;
      *) lg_error "Some classic snaps failed. See $LG_LOG_DIR/apps"; failed=1 ;;
    esac
  fi
  if [ "$cancelled" -eq 1 ]; then
    lg_warn "Cancelled: the password prompt was dismissed. Anything not listed as installed above was not changed."
    return 2
  fi
  lg_record_incident "maintenance" "info" "Installed apps from an app list via LinuxGuardian"
  [ "$failed" -eq 0 ]
}

case "$MODE" in
  export) do_export ;;
  plan) do_plan ;;
  install) do_install ;;
esac

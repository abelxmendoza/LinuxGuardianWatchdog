#!/usr/bin/env bash
# linux_updates.sh — check for and install software updates (apt + snap).
#
# Usage:
#   linux_updates.sh --check [--json] [--no-snap]   What is pending (no root needed)
#   linux_updates.sh --summary [--no-snap]          One line of counts
#   linux_updates.sh --apply [--security-only]      Install updates (asks for your password)
#   linux_updates.sh --apply --dry-run              Show what would be installed; changes nothing
#   linux_updates.sh --hold GROUP                   Freeze a stack so nothing updates it
#   linux_updates.sh --unhold GROUP                 Let a frozen stack update again
#                                                   (GROUP: ros2, gazebo, nvidia)
#   linux_updates.sh -h | --help
#
# Exit codes: 0 ok, 1 errors, 2 password prompt cancelled, 3 blocked by the
# release guard.
#
# Release guard: before installing anything, every update source and pending
# package is checked against the Ubuntu release this machine is running. If
# anything points at a different release, nothing is installed. A stray
# sources edit can't quietly turn a routine update into a partial release
# upgrade. There is deliberately no override flag.
#
# How privileges work: installing needs root, and there is no passwordless
# sudo to lean on. --apply asks the desktop's own polkit prompt (pkexec) for
# your password; this script never sees, stores, or passes it anywhere. Only
# the fixed, hard-coded package-manager commands below are ever run as root.
#
# What it will NOT do: remove packages, or run a full/dist upgrade. Packages
# that need that (e.g. a GPU driver version change) are reported as "held
# back" and left for you to review, because they can change the system in ways
# a one-click button shouldn't decide for you.
set -uo pipefail
# Byte-wise ranges: [a-z] must never match uppercase via locale collation.
export LC_ALL=C

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"
# shellcheck source=utils.sh
source "$SCRIPT_DIR/utils.sh"

INVENTORY="$SCRIPT_DIR/update_inventory.py"

# Print only the leading comment block (this file has comments further down
# that must not leak into --help).
usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

MODE="" JSON=0 NO_SNAP=0 SECURITY_ONLY=0 DRY_RUN=0 HOLD_GROUP=""

if [ $# -eq 0 ]; then
  usage
  exit 0
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE="check" ;;
    --summary) MODE="summary" ;;
    --apply) MODE="apply" ;;
    --json) JSON=1 ;;
    --no-snap) NO_SNAP=1 ;;
    --security-only) SECURITY_ONLY=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --hold|--unhold)
      MODE="${1#--}"
      if [ $# -lt 2 ]; then lg_error "$1 needs a group (ros2, gazebo, nvidia)"; exit 1; fi
      HOLD_GROUP="$2"
      shift
      ;;
    -h|--help) usage; exit 0 ;;
    *) lg_error "Unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done

if [ -z "$MODE" ]; then
  usage
  exit 0
fi

inventory_args=()
[ "$NO_SNAP" -eq 1 ] && inventory_args+=(--no-snap)

# The privileged scripts. These are fixed strings — nothing from the user,
# the environment, or a file is ever interpolated into them — so what runs as
# root is exactly what you can read here.
#
# apt-get upgrade (not full-upgrade): never removes packages, and keeps back
# anything that would need new/removed dependencies.
PRIV_SCRIPT_ALL='
export DEBIAN_FRONTEND=noninteractive
rc=0
echo "LG_PROGRESS|phase=updates|message=Refreshing package lists|step=1|steps=3"
apt-get update || rc=1
echo "LG_PROGRESS|phase=updates|message=Installing system and app updates|step=2|steps=3"
apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade || rc=1
if command -v snap >/dev/null 2>&1; then
  echo "LG_PROGRESS|phase=updates|message=Refreshing snap apps|step=3|steps=3"
  snap refresh || rc=1
fi
exit $rc
'

# Security-only reuses unattended-upgrade, the same tool that applies Ubuntu's
# daily security patches: it only touches the security pockets by design.
PRIV_SCRIPT_SECURITY='
export DEBIAN_FRONTEND=noninteractive
rc=0
echo "LG_PROGRESS|phase=updates|message=Refreshing package lists|step=1|steps=2"
apt-get update || rc=1
echo "LG_PROGRESS|phase=updates|message=Installing security updates|step=2|steps=2"
unattended-upgrade -v || rc=1
exit $rc
'

# Hold/release. Unlike the scripts above this one has to be told WHICH
# packages, so they arrive as positional arguments ("$@"), never spliced into
# the script text, and are re-validated here as root: only a hold/unhold
# action, and only names shaped like Debian package names (no leading '-', no
# uppercase, no shell or option syntax).
PRIV_SCRIPT_MARK='
act=$1
shift
case "$act" in
  hold|unhold) ;;
  *) echo "refusing unknown action" >&2; exit 2 ;;
esac
if [ "$#" -eq 0 ]; then
  echo "no packages given" >&2
  exit 2
fi
for p in "$@"; do
  case "$p" in
    ""|-*|*[!a-z0-9+.:-]*) echo "refusing invalid package name" >&2; exit 2 ;;
  esac
done
exec apt-mark "$act" "$@"
'

do_check() {
  if [ "$JSON" -eq 1 ]; then
    python3 "$INVENTORY" ${inventory_args[@]+"${inventory_args[@]}"}
  else
    python3 "$INVENTORY" --text ${inventory_args[@]+"${inventory_args[@]}"}
  fi
}

do_summary() {
  python3 "$INVENTORY" --summary ${inventory_args[@]+"${inventory_args[@]}"}
}

# Hard stop if any update source or pending package is for another release.
# Returns 3 when blocked. Runs before dry-runs too, so a preview never says
# "fine" about something the real run would refuse.
release_guard() {
  local out rc
  out="$(python3 "$INVENTORY" --guard 2>&1)"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    return 0
  fi
  lg_error "Refusing to install: the release guard found a problem."
  while IFS= read -r line; do
    [ -n "$line" ] && echo "  $line"
  done <<< "$out"
  lg_info "Nothing was installed. This guard exists so a mistaken sources edit can't turn an"
  lg_info "ordinary update into a half-finished release upgrade. Fix or remove the source above,"
  lg_info "then try again."
  return 3
}

do_hold() {
  local action="$MODE" group="$HOLD_GROUP" names=() name rc out
  out="$(python3 "$INVENTORY" "--${action}-names" "$group" 2>/dev/null)"
  rc=$?
  if [ "$rc" -eq 4 ]; then
    lg_error "Unknown stack '$group'. Use one of: ros2, gazebo, nvidia."
    return 1
  elif [ "$rc" -ne 0 ]; then
    lg_error "Couldn't list packages for '$group'."
    return 1
  fi
  [ -n "$out" ] && mapfile -t names <<< "$out"
  if [ "${#names[@]}" -eq 0 ]; then
    lg_ok "Nothing to $action for '$group' (already ${action}ed, or not installed)."
    return 0
  fi
  # Second line of defence: the root-side script re-checks, but never hand it
  # anything that isn't shaped like a package name.
  for name in "${names[@]}"; do
    if ! [[ "$name" =~ ^[a-z0-9][a-z0-9+.:-]*$ ]]; then
      lg_error "Refusing to pass an invalid package name to root: $name"
      return 1
    fi
  done

  local log_dir="$LG_LOG_DIR/updates" log
  mkdir -p "$log_dir"
  log="$log_dir/${action}-$(date '+%Y%m%d-%H%M%S').log"

  lg_info "${action^}ing ${#names[@]} '$group' packages. A system password prompt will appear."
  trap '' PIPE
  lg_run_privileged "$PRIV_SCRIPT_MARK" "$action" "${names[@]}" 2>&1 | lg_tee_log "$log"
  rc=${PIPESTATUS[0]}

  if [ "$rc" -eq 126 ] || [ "$rc" -eq 127 ]; then
    lg_warn "The password prompt was cancelled or authentication failed. Nothing was changed."
    return 2
  fi
  if [ "$rc" -ne 0 ]; then
    lg_error "apt-mark $action failed. Log: $log"
    return 1
  fi
  lg_ok "${action^}ed ${#names[@]} '$group' packages."
  lg_record_incident "maintenance" "info" "apt-mark $action on ${#names[@]} '$group' packages via LinuxGuardian"
  return 0
}

do_apply() {
  local label="all updates"
  [ "$SECURITY_ONLY" -eq 1 ] && label="security updates only"

  release_guard || return $?

  if [ "$DRY_RUN" -eq 1 ]; then
    lg_info "Dry run ($label): nothing will be installed and no password is needed."
    do_check
    return 0
  fi

  if ! command -v pkexec >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    lg_error "pkexec (polkit) is not installed, so there is no safe way to ask for your password from here."
    lg_info "Run this yourself instead:  sudo apt update && sudo apt upgrade"
    return 1
  fi

  # From here on a vanished reader (GUI closed) must not kill this script
  # before it records the result.
  trap '' PIPE

  local script="$PRIV_SCRIPT_ALL"
  [ "$SECURITY_ONLY" -eq 1 ] && script="$PRIV_SCRIPT_SECURITY"

  local log_dir="$LG_LOG_DIR/updates" log
  mkdir -p "$log_dir"
  log="$log_dir/apply-$(date '+%Y%m%d-%H%M%S').log"

  lg_info "Installing $label. A system password prompt will appear."
  lg_info "This can't be safely interrupted once it starts; closing the window won't stop it."
  lg_progress "updates" "Waiting for your password" "step=0" "pct=0"

  local rc
  lg_run_privileged "$script" 2>&1 | lg_tee_log "$log"
  rc=${PIPESTATUS[0]}

  # pkexec: 126 = not authorized / auth failed, 127 = prompt dismissed.
  # Our own scripts only ever exit 0 or 1, so these can't be confused.
  if [ "$rc" -eq 126 ] || [ "$rc" -eq 127 ]; then
    lg_warn "The password prompt was cancelled or authentication failed. Nothing was installed."
    return 2
  fi

  if [ "$rc" -ne 0 ]; then
    lg_error "The update run finished with errors. Full log: $log"
    lg_record_incident "maintenance" "warning" "Update run ($label) finished with errors; see $log"
    return 1
  fi

  lg_progress "updates" "Updates installed" "pct=100"
  lg_ok "Update run finished ($label). Log: $log"
  lg_record_incident "maintenance" "info" "Installed $label via LinuxGuardian"

  local summary
  summary="$(python3 "$INVENTORY" --summary --no-snap 2>/dev/null || true)"
  if [[ "$summary" == *"reboot=1"* ]]; then
    lg_warn "A restart is needed to finish applying some updates (kernel or core libraries)."
  fi
  return 0
}

case "$MODE" in
  check) do_check ;;
  summary) do_summary ;;
  apply) do_apply ;;
  hold|unhold) do_hold ;;
esac

#!/usr/bin/env bash
# linux_ros_firewall.sh — narrow ufw rules so a robot can reach this laptop's ROS 2 (preview first).
#
# Usage:
#   linux_ros_firewall.sh --detect                          What this laptop says about its ROS setup
#   linux_ros_firewall.sh --plan  --peer ADDR [--domain N] [--preset NAME]...
#                                                          Show the exact rules and what they allow (changes nothing)
#   linux_ros_firewall.sh --apply --peer ADDR [--domain N] [--preset NAME]...
#                                                          Add those rules (one password prompt)
#   linux_ros_firewall.sh --remove --peer ADDR [--domain N] [--preset NAME]...
#                                                          Take the same rules away again
#   Presets: mavlink, xrce, foxglove, rosbridge. The ROS 2 (DDS) rule for your domain is always included.
#   linux_ros_firewall.sh -h | --help
#
# Only ever ADDS or REMOVES the rules it prints. It never changes ufw's default policy, never turns ufw on or
# off, and refuses unless ufw is the active firewall. Peers are single addresses or networks no wider than /16.
# Exit: 0 ok, 1 error, 2 cancelled, 3 refused.
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"
# shellcheck source=utils.sh
source "$SCRIPT_DIR/utils.sh"

usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

# What runs as root. FIXED text. Rules arrive as groups of 4 words in "$@" (name proto ports peer), each
# re-validated here; the comment is built here from an allow-list, never taken from outside.
PRIV_SCRIPT_UFW_RULES='
act=$1
shift
case "$act" in
  add|remove) ;;
  *) echo "refusing unknown action" >&2; exit 2 ;;
esac
if [ "$#" -eq 0 ] || [ $(( $# % 4 )) -ne 0 ]; then echo "rules must come in groups of four" >&2; exit 2; fi
# Pass 1: validate every group (rotating the arguments, no indirection) before any rule is touched.
count=$(( $# / 4 ))
while [ "$count" -gt 0 ]; do
  name=$1; proto=$2; ports=$3; peer=$4
  shift 4
  case "$name" in dds|mavlink|xrce|foxglove|rosbridge) ;; *) echo "refusing unknown rule name" >&2; exit 2 ;; esac
  case "$proto" in udp|tcp) ;; *) echo "refusing protocol" >&2; exit 2 ;; esac
  case "$ports" in ""|*[!0-9:,]*) echo "refusing ports" >&2; exit 2 ;; esac
  case "$peer" in ""|*[!0-9a-fA-F:./]*) echo "refusing address" >&2; exit 2 ;; esac
  set -- "$@" "$name" "$proto" "$ports" "$peer"
  count=$((count-1))
done
rc=0
while [ "$#" -gt 0 ]; do
  name=$1; proto=$2; ports=$3; peer=$4
  shift 4
  if [ "$act" = add ]; then
    ufw allow from "$peer" to any port "$ports" proto "$proto" comment "LinuxGuardian ROS $name" || rc=1
  else
    ufw delete allow from "$peer" to any port "$ports" proto "$proto" || rc=1
  fi
done
exit $rc
'

MODE="" PEER="" DOMAIN="" PRESETS=()
case "${1:-}" in
  --detect|--plan|--apply|--remove) MODE="${1#--}"; shift ;;
  -h|--help|"") usage; exit 0 ;;
  *) lg_error "Unknown option: $1"; usage; exit 1 ;;
esac
while [ $# -gt 0 ]; do
  case "$1" in
    --peer) PEER="${2:-}"; shift ;;
    --domain) DOMAIN="${2:-}"; shift ;;
    --preset) PRESETS+=("${2:-}"); shift ;;
    *) lg_error "Unknown option: $1"; exit 1 ;;
  esac
  shift
done

PY="$SCRIPT_DIR/ros_firewall.py"
plan_args() {
  local a=(--peer "$PEER")
  [ -n "$DOMAIN" ] && a+=(--domain "$DOMAIN")
  local p
  for p in ${PRESETS[@]+"${PRESETS[@]}"}; do a+=(--preset "$p"); done
  printf '%s\n' "${a[@]}"
}

case "$MODE" in
  detect) exec python3 "$PY" --detect ;;
  plan)
    mapfile -t args < <(plan_args)
    python3 "$PY" --plan "${args[@]}"; exit $?
    ;;
esac

# apply / remove
[ -n "$PEER" ] || { lg_error "--peer is required."; exit 3; }
fw="$(lg_detect_firewall)"
if [ "$fw" != "ufw" ]; then
  lg_error "ufw is not the active firewall here (detected: $fw), so there is nothing for these rules to change. Nothing was done."
  exit 3
fi
mapfile -t args < <(plan_args)
plan_json="$(python3 "$PY" --plan "${args[@]}" --json 2>&1)" || { lg_error "$plan_json"; exit 3; }
mapfile -t fields < <(python3 -c '
import json, sys
for r in json.load(sys.stdin)["rules"]:
    print(r["name"]); print(r["proto"]); print(r["ports"]); print(r["peer"])
' <<<"$plan_json")
n=$(( ${#fields[@]} / 4 ))
# Second line of defence: nothing odd goes to root.
i=0
while [ "$i" -lt "${#fields[@]}" ]; do
  [[ "${fields[i]}" =~ ^(dds|mavlink|xrce|foxglove|rosbridge)$ ]] \
    && [[ "${fields[i+1]}" =~ ^(udp|tcp)$ ]] \
    && [[ "${fields[i+2]}" =~ ^[0-9]+([:,][0-9]+)*$ ]] \
    && [[ "${fields[i+3]}" =~ ^[0-9a-fA-F:./]+$ ]] \
    || { lg_error "Refusing to pass an unexpected rule to root."; exit 3; }
  i=$((i+4))
done

action=add
[ "$MODE" = "remove" ] && action=remove
lg_info "${action^}ing $n firewall rule(s) for $PEER (the desktop will ask for your password)..."
log_dir="$LG_LOG_DIR/ros-firewall"; mkdir -p "$log_dir"
log="$log_dir/$action-$(date '+%Y%m%d-%H%M%S').log"
trap '' PIPE
lg_run_privileged "$PRIV_SCRIPT_UFW_RULES" "$action" "${fields[@]}" 2>&1 | lg_tee_log "$log"
rc=${PIPESTATUS[0]}
case "$rc" in
  0) lg_ok "Done. Default policy unchanged (still deny); only these rules were ${action}ed."
     lg_record_incident "network" "info" "ROS firewall: ${action}ed $n ufw rule(s) for $PEER via LinuxGuardian" ;;
  126|127) lg_warn "Cancelled: the password prompt was dismissed. Nothing was changed."; exit 2 ;;
  *) lg_error "ufw reported an error. See $log"; exit 1 ;;
esac

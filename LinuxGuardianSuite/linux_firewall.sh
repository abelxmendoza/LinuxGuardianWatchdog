#!/usr/bin/env bash
# linux_firewall.sh — see and control the ufw firewall: status, rules, defaults, logging (changes are previewed first).
#
# Usage:
#   linux_firewall.sh --status [--json]                     On/off, default policies, logging, service health (no root)
#   linux_firewall.sh --blocks [--json]                     What the firewall blocked recently (no root; needs the 'adm' group)
#   linux_firewall.sh --rules                               List the numbered rules (one password prompt; read-only)
#   linux_firewall.sh --plan-add --action A --port P [--proto tcp|udp|any] [--from ADDR] [--label TEXT]
#                                                          Show the exact rule and what it allows (changes nothing)
#   linux_firewall.sh --add --action A --port P [--proto X] [--from ADDR] [--label TEXT]
#                                                          Add that rule. A = allow, deny, reject or limit
#   linux_firewall.sh --delete N --fingerprint HEX          Delete rule N, only if it is still the rule you saw
#   linux_firewall.sh --enable | --disable                  Turn ufw on or off
#   linux_firewall.sh --restart                             Restart the ufw service (reloads every rule)
#   linux_firewall.sh --default-incoming deny|reject        Default for connections coming in
#   linux_firewall.sh --default-outgoing allow|deny         Default for connections going out
#   linux_firewall.sh --logging off|low|medium|high|full    How much ufw writes to /var/log/ufw.log
#   linux_firewall.sh -h | --help
#
# Every change goes through ONE fixed root script that re-checks its arguments, and ends by printing the rules again.
# It refuses when firewalld or nftables is in charge (two firewalls fighting is worse than one). Each change is logged
# to ~/.linuxguardian/logs/firewall/ and recorded as an event.
# Exit: 0 ok, 1 error, 2 cancelled, 3 refused, 4 the rule changed since you looked (nothing deleted).
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"
# shellcheck source=utils.sh
source "$SCRIPT_DIR/utils.sh"

usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

# What runs as root. FIXED text: every argument is re-validated here against an allow-list before ufw sees it.
PRIV_SCRIPT_FIREWALL='
refuse() { echo "refusing: $1" >&2; exit 3; }
show_rules() { echo LG_RULES_BEGIN; ufw status numbered; echo LG_RULES_END; }
act=$1
shift
case "$act" in
  rules) show_rules; exit $? ;;
  enable) [ "$#" -eq 0 ] || refuse "arguments"; ufw --force enable || exit 1 ;;
  disable) [ "$#" -eq 0 ] || refuse "arguments"; ufw disable || exit 1 ;;
  restart)
    [ "$#" -eq 0 ] || refuse "arguments"
    if ! systemctl restart ufw; then
      journalctl -u ufw -b -n 6 --no-pager -o cat 2>/dev/null
      show_rules
      exit 1
    fi ;;
  default)
    [ "$#" -eq 2 ] || refuse "arguments"
    case "$1:$2" in incoming:deny|incoming:reject|outgoing:allow|outgoing:deny) ;; *) refuse "policy" ;; esac
    ufw default "$2" "$1" || exit 1 ;;
  logging)
    [ "$#" -eq 1 ] || refuse "arguments"
    case "$1" in off|low|medium|high|full) ;; *) refuse "log level" ;; esac
    ufw logging "$1" || exit 1 ;;
  add)
    [ "$#" -eq 5 ] || refuse "arguments"
    action=$1; proto=$2; port=$3; src=$4; label=$5
    case "$action" in allow|deny|reject|limit) ;; *) refuse "action" ;; esac
    case "$proto" in tcp|udp|any) ;; *) refuse "protocol" ;; esac
    case "$port" in ""|:*|*:|*:*:*|*[!0-9:]*) refuse "port" ;; esac
    case "$src" in any) ;; ""|-*|*[!0-9a-fA-F:./]*) refuse "address" ;; esac
    case "$label" in *[!A-Za-z0-9\ ._-]*) refuse "label" ;; esac
    [ "${#label}" -le 40 ] || refuse "label"
    comment=LinuxGuardian
    [ -n "$label" ] && comment="LinuxGuardian: $label"
    if [ "$proto" = any ]; then
      ufw "$action" from "$src" to any port "$port" comment "$comment" || exit 1
    else
      ufw "$action" proto "$proto" from "$src" to any port "$port" comment "$comment" || exit 1
    fi ;;
  delete)
    [ "$#" -eq 2 ] || refuse "arguments"
    n=$1; fp=$2
    case "$n" in ""|0*|*[!0-9]*) refuse "rule number" ;; esac
    case "$fp" in *[!0-9a-f]*) refuse "fingerprint" ;; esac
    [ "${#fp}" -eq 64 ] || refuse "fingerprint"
    line=$(ufw status numbered | grep -E "^\[ *$n\]" | sed "s/[[:space:]]*\$//")
    now=$(printf "%s" "$line" | sha256sum | cut -c1-64)
    if [ -z "$line" ] || [ "$now" != "$fp" ]; then
      echo "Rule $n is not the rule you were shown any more (the list changed). Nothing was deleted." >&2
      show_rules
      exit 4
    fi
    ufw --force delete "$n" || exit 1 ;;
  *) refuse "unknown action" ;;
esac
show_rules
'

MODE="" JSON=0 R_ACTION="" R_PORT="" R_PROTO="tcp" R_FROM="" R_LABEL="" DEL_N="" DEL_FP="" VALUE=""
case "${1:-}" in
  --status|--blocks|--rules|--plan-add|--add|--enable|--disable|--restart) MODE="${1#--}"; shift ;;
  --delete) MODE="delete"; DEL_N="${2:-}"; shift; shift ;;
  --default-incoming|--default-outgoing|--logging) MODE="${1#--}"; VALUE="${2:-}"; shift; shift ;;
  -h|--help|"") usage; exit 0 ;;
  *) lg_error "Unknown option: $1"; usage; exit 1 ;;
esac
while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON=1 ;;
    --action) R_ACTION="${2:-}"; shift ;;
    --port) R_PORT="${2:-}"; shift ;;
    --proto) R_PROTO="${2:-}"; shift ;;
    --from) R_FROM="${2:-}"; shift ;;
    --label) R_LABEL="${2:-}"; shift ;;
    --fingerprint) DEL_FP="${2:-}"; shift ;;
    *) lg_error "Unknown option: $1"; exit 1 ;;
  esac
  shift
done

PY="$SCRIPT_DIR/firewall_control.py"
json_flag=()
[ "$JSON" -eq 1 ] && json_flag=(--json)
plan_args=(--action "$R_ACTION" --port "$R_PORT" --proto "$R_PROTO" --from "$R_FROM" --label "$R_LABEL")

case "$MODE" in
  status) exec python3 "$PY" --status --kind "$(lg_detect_firewall)" ${json_flag[@]+"${json_flag[@]}"} ;;
  blocks) exec python3 "$PY" --blocks ${json_flag[@]+"${json_flag[@]}"} ;;
  plan-add) exec python3 "$PY" --plan-add "${plan_args[@]}" ;;
esac

# Everything below talks to root.
command -v ufw >/dev/null 2>&1 \
  || { lg_error "ufw isn't installed (sudo apt install ufw). Nothing was done."; exit 3; }
fw="$(lg_detect_firewall)"
if [ "$fw" = "firewalld" ] || [ "$fw" = "nftables" ]; then
  lg_error "$fw is managing the firewall here; changing ufw as well would leave two firewalls fighting. Nothing was done."
  exit 3
fi

# What was there before, so the change ledger (login_watch.py) can say how to put it back.
before_json="$(python3 "$PY" --status --json 2>/dev/null || true)"
before() { python3 -c 'import json,sys; d=json.loads(sys.argv[1] or "{}"); print(d.get("policies",{}).get(sys.argv[2]) if sys.argv[2]!="logging" else d.get("logging",""))' "$before_json" "$1" 2>/dev/null; }
priv_args=() note="" undo=""
case "$MODE" in
  rules) priv_args=(rules) ;;
  enable) priv_args=(enable); note="Firewall turned ON from LinuxGuardian"; undo="$0 --disable" ;;
  disable) priv_args=(disable); note="Firewall turned OFF from LinuxGuardian"; undo="$0 --enable" ;;
  restart) priv_args=(restart); note="Firewall service restarted from LinuxGuardian"; undo="nothing to undo (a restart only reloads the rules)" ;;
  default-incoming|default-outgoing)
    dir="${MODE#default-}"
    case "$dir:$VALUE" in incoming:deny|incoming:reject|outgoing:allow|outgoing:deny) ;;
      *) lg_error "Default $dir policy must be $( [ "$dir" = incoming ] && echo 'deny or reject' || echo 'allow or deny')."; exit 3 ;;
    esac
    priv_args=(default "$dir" "$VALUE"); note="Firewall default for $dir connections set to $VALUE from LinuxGuardian"
    undo="$0 --default-$dir $(before "$dir")" ;;
  logging)
    [[ "$VALUE" =~ ^(off|low|medium|high|full)$ ]] || { lg_error "Logging must be off, low, medium, high or full."; exit 3; }
    priv_args=(logging "$VALUE"); note="Firewall logging set to $VALUE from LinuxGuardian"; undo="$0 --logging $(before logging)" ;;
  add)
    plan_json="$(python3 "$PY" --plan-add "${plan_args[@]}" --json 2>&1)" || { lg_error "$plan_json"; exit 3; }
    mapfile -t f < <(python3 -c '
import json, sys
p = json.load(sys.stdin)
for k in ("action", "proto", "ports", "from", "label"):
    print(p[k])
' <<<"$plan_json")
    # Second line of defence: nothing odd goes to root.
    [ "${#f[@]}" -eq 5 ] \
      && [[ "${f[0]}" =~ ^(allow|deny|reject|limit)$ ]] && [[ "${f[1]}" =~ ^(tcp|udp|any)$ ]] \
      && [[ "${f[2]}" =~ ^[0-9]+(:[0-9]+)?$ ]] && [[ "${f[3]}" =~ ^(any|[0-9a-fA-F:./]+)$ ]] \
      && [[ "${f[4]}" =~ ^[A-Za-z0-9\ ._-]{0,40}$ ]] \
      || { lg_error "Refusing to pass an unexpected rule to root."; exit 3; }
    priv_args=(add "${f[@]}"); note="Firewall rule added from LinuxGuardian: ${f[0]} ${f[1]} port ${f[2]} from ${f[3]}"
    undo="delete it in the Firewall tab, or: sudo ufw delete ${f[0]}$( [ "${f[1]}" = any ] || echo " proto ${f[1]}") from ${f[3]} to any port ${f[2]}" ;;
  delete)
    [[ "$DEL_N" =~ ^[1-9][0-9]{0,4}$ ]] || { lg_error "--delete needs a rule number."; exit 3; }
    [[ "$DEL_FP" =~ ^[0-9a-f]{64}$ ]] || { lg_error "--delete needs the --fingerprint of the rule you were shown (list the rules first)."; exit 3; }
    priv_args=(delete "$DEL_N" "$DEL_FP"); note="Firewall rule $DEL_N deleted from LinuxGuardian"
    undo="add the rule again in the Firewall tab (its text is in the log under ~/.linuxguardian/logs/firewall/)" ;;
esac

[ "$MODE" = rules ] || lg_info "Changing the firewall (the desktop will ask for your password)..."
log_dir="$LG_LOG_DIR/firewall"; mkdir -p "$log_dir"
log="$log_dir/$MODE-$(date '+%Y%m%d-%H%M%S').log"
trap '' PIPE
lg_run_privileged "$PRIV_SCRIPT_FIREWALL" "${priv_args[@]}" 2>&1 | lg_tee_log "$log"
rc=${PIPESTATUS[0]}
case "$rc" in
  0) if [ -n "$note" ]; then
       lg_ok "Done."
       severity=info
       [ "$MODE" = disable ] && severity=warning
       lg_record_incident "network" "$severity" "$note"
       python3 "$SCRIPT_DIR/login_watch.py" --mark-change "$note" --undo "$undo" || true
     fi ;;
  126|127) lg_warn "Cancelled: the password prompt was dismissed. Nothing was changed."; exit 2 ;;
  3) lg_error "Refused by the root script. Nothing was changed."; exit 3 ;;
  4) exit 4 ;;
  *) lg_error "ufw reported an error. See $log"; exit 1 ;;
esac

#!/usr/bin/env bash
# Shared helper functions for LinuxGuardian Suite scripts.
# Sourced by every other script in this directory — do not execute directly.

lg_log() {
  local level="$1"; shift
  local msg="$*"
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "[$ts] [$level] $msg" >> "$LG_LOG_FILE"
}

lg_info()  { echo "${LG_C_BLUE}[INFO]${LG_C_RESET} $*";  lg_log INFO  "$*"; }
lg_ok()    { echo "${LG_C_GREEN}[ OK ]${LG_C_RESET} $*"; lg_log OK    "$*"; }
lg_warn()  { echo "${LG_C_YELLOW}[WARN]${LG_C_RESET} $*"; lg_log WARN  "$*"; }
lg_error() { echo "${LG_C_RED}[FAIL]${LG_C_RESET} $*" >&2; lg_log ERROR "$*"; }

lg_require_cmd() {
  local cmd="$1"
  local hint="${2:-}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    lg_error "'$cmd' is not installed.${hint:+ $hint}"
    return 1
  fi
  return 0
}

# Detects the system's active firewall front-end, if any.
lg_detect_firewall() {
  local status unknown=0
  if command -v ufw >/dev/null 2>&1; then
    if status="$(LC_ALL=C ufw status 2>/dev/null)"; then
      if grep -Eq '^Status: active$' <<< "$status"; then
        echo "ufw"; return
      fi
    else
      unknown=1
    fi
  fi
  if command -v firewall-cmd >/dev/null 2>&1; then
    if status="$(firewall-cmd --state 2>/dev/null)" && [ "$status" = "running" ]; then
      echo "firewalld"; return
    fi
    unknown=1
  fi
  # Raw rules need interpretation; their mere presence does not prove protection.
  if command -v nft >/dev/null 2>&1; then
    if status="$(nft list ruleset 2>/dev/null)"; then
      [ -z "$status" ] || unknown=1
    else
      unknown=1
    fi
  elif command -v iptables >/dev/null 2>&1; then
    unknown=1
  fi
  if [ "$unknown" -eq 1 ]; then echo "unknown"; else echo "none"; fi
}

# Records a structured incident for the GUI to pick up later.
lg_record_incident() {
  local category="$1" severity="$2" message="$3"
  local ts file
  ts="$(date '+%Y-%m-%dT%H:%M:%S%z')"
  file="$LG_INCIDENT_DIR/$(date '+%Y%m%d-%H%M%S')-$$-$RANDOM.json"
  printf '{"timestamp":"%s","category":"%s","severity":"%s","message":"%s"}\n' \
    "$ts" "$category" "$severity" "${message//\"/\\\"}" > "$file"
}

lg_fmt_duration() {
  local s="${1:-0}"
  [[ "$s" =~ ^[0-9]+$ ]] || s=0
  local h=$((s / 3600)) m=$(((s % 3600) / 60)) sec=$((s % 60))
  if [ "$h" -gt 0 ]; then
    printf '%dh %dm' "$h" "$m"
  elif [ "$m" -gt 0 ]; then
    printf '%dm %02ds' "$m" "$sec"
  else
    printf '%ds' "$s"
  fi
}

# Machine-readable progress for the GUI. Values cannot contain '|' or newlines.
# Usage: lg_progress PHASE MESSAGE [key=value ...]
lg_progress() {
  local phase="${1:-}" message="${2:-}"
  shift $(( $# >= 2 ? 2 : $# ))
  local out="LG_PROGRESS|phase=$(_lg_progress_sanitize "$phase")"
  [ -n "$message" ] && out+="|message=$(_lg_progress_sanitize "$message")"
  local kv
  for kv in "$@"; do
    out+="|$(_lg_progress_sanitize "$kv")"
  done
  echo "$out"
}

_lg_progress_sanitize() {
  printf '%s' "$1" | tr '|\r\n' '   '
}

lg_cmd_has_flag() {
  local cmd="$1" flag="$2"
  command -v "$cmd" >/dev/null 2>&1 || return 1
  "$cmd" --help 2>&1 | grep -qE -- "(^|[[:space:]])${flag}([[:space:]]|$)"
}

_lg_descendant_pids() {
  local pid="$1" child
  echo "$pid"
  for child in $(ps -o pid= --ppid "$pid" 2>/dev/null); do
    child="${child// /}"
    [ -n "$child" ] && _lg_descendant_pids "$child"
  done
}

_lg_find_named_pid() {
  local want="$1" root="${2:-$$}" pid comm
  while IFS= read -r pid; do
    pid="${pid// /}"
    [ -n "$pid" ] || continue
    comm="$(ps -o comm= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
    if [ "$comm" = "$want" ]; then
      printf '%s\n' "$pid"
      return 0
    fi
  done < <(_lg_descendant_pids "$root")
  return 1
}

# Best-effort "file this scanner currently has open" from /proc.
_lg_scan_current_path() {
  local root_pid="$1"
  [ -n "$root_pid" ] || return 0
  local pid fd target exe
  while IFS= read -r pid; do
    pid="${pid// /}"
    [ -d "/proc/$pid/fd" ] || continue
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
    for fd in /proc/$pid/fd/*; do
      target="$(readlink "$fd" 2>/dev/null)" || continue
      [ -n "$exe" ] && [ "$target" = "$exe" ] && continue
      case "${target##*/}" in
        clamscan|rkhunter|tee|stdbuf|tr|bash|dash|sh) continue ;;
      esac
      case "$target" in
        /dev/*|/proc/*|/sys/*|socket:*|pipe:*|anon_inode:*) continue ;;
        */linuxguardian/*|*/.linuxguardian/*) continue ;;
        /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*|/usr/lib/*|/lib/*|/usr/lib64/*|/lib64/*) continue ;;
        *.so|*.so.*) continue ;;
      esac
      if [ -f "$target" ]; then
        printf '%s\n' "$target"
        return 0
      fi
    done
  done < <(_lg_descendant_pids "$root_pid")
}

_lg_last_pct() {
  local file="$1"
  [ -f "$file" ] || return 0
  local snippet pct=""
  snippet="$(tail -c 4096 "$file" 2>/dev/null | tr '\r' '\n')"
  while [[ "$snippet" =~ ([0-9]{1,3})% ]]; do
    pct="${BASH_REMATCH[1]}"
    snippet="${snippet#*"${BASH_REMATCH[0]}"}"
  done
  if [[ "$pct" =~ ^[0-9]+$ ]] && [ "$pct" -le 100 ]; then
    printf '%s\n' "$pct"
  fi
}

_lg_last_eta_sec() {
  local file="$1"
  [ -f "$file" ] || return 0
  local snippet eta=""
  snippet="$(tail -c 4096 "$file" 2>/dev/null | tr '\r' '\n')"
  while [[ "$snippet" =~ ([Ee][Tt][Aa]|[Rr]emaining)[:[:space:]]*([0-9]{1,2}):([0-9]{2})(:([0-9]{2}))? ]]; do
    if [ -n "${BASH_REMATCH[5]}" ]; then
      eta=$((10#${BASH_REMATCH[2]} * 3600 + 10#${BASH_REMATCH[3]} * 60 + 10#${BASH_REMATCH[5]}))
    else
      eta=$((10#${BASH_REMATCH[2]} * 60 + 10#${BASH_REMATCH[3]}))
    fi
    snippet="${snippet#*"${BASH_REMATCH[0]}"}"
  done
  [ -n "$eta" ] && printf '%s\n' "$eta"
}

# Heartbeat every second while PID is alive. Optional LOGFILE is tailed for
# percent/ETA (ClamAV --progress uses CR redraws). Extra args (step=/steps=)
# are appended on every tick. Returns the waited command's exit status.
# Usage: lg_watch_pid PID PHASE MESSAGE LOGFILE [key=value ...]
lg_watch_pid() {
  local pid="$1" phase="$2" message="$3" logfile="${4:-}"
  shift $(( $# >= 4 ? 4 : $# ))
  local start elapsed current pct eta tick_msg extras last_human=0
  start="$(date +%s)"
  while kill -0 "$pid" 2>/dev/null; do
    elapsed=$(( $(date +%s) - start ))
    local scan_pid="$pid" named=""
    case "$phase" in
      clamav) named="$(_lg_find_named_pid clamscan || true)" ;;
      rkhunter) named="$(_lg_find_named_pid rkhunter || true)" ;;
    esac
    [ -n "$named" ] && scan_pid="$named"
    current="$(_lg_scan_current_path "$scan_pid")"
    pct=""
    eta=""
    [ -n "$logfile" ] && pct="$(_lg_last_pct "$logfile")"
    [ -n "$logfile" ] && eta="$(_lg_last_eta_sec "$logfile")"
    tick_msg="$message"
    case "$current" in
      *.cvd|*.cld|*.cud) tick_msg="Loading virus signatures" ;;
    esac
    extras=("elapsed_sec=$elapsed" "$@")
    [ -n "$current" ] && extras+=("current=$current")
    [ -n "$pct" ] && extras+=("pct=$pct")
    [ -n "$eta" ] && extras+=("eta_sec=$eta")
    lg_progress "$phase" "$tick_msg ($(lg_fmt_duration "$elapsed") elapsed)" "${extras[@]}"
    if [ $((elapsed - last_human)) -ge 15 ]; then
      last_human="$elapsed"
      if [ -n "$current" ]; then
        lg_info "$tick_msg — $(lg_fmt_duration "$elapsed") elapsed, still running; current: $current"
      else
        lg_info "$tick_msg — $(lg_fmt_duration "$elapsed") elapsed, still running (not frozen)"
      fi
    fi
    sleep 1
  done
  wait "$pid" 2>/dev/null
}

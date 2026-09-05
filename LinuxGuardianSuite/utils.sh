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
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
    echo "ufw"
  elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "firewalld"
  elif command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q .; then
    echo "nftables"
  elif command -v iptables >/dev/null 2>&1 && iptables -L 2>/dev/null | grep -qv "^Chain.*(policy ACCEPT)$"; then
    echo "iptables"
  else
    echo "none"
  fi
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

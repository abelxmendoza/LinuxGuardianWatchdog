#!/usr/bin/env bash
# shellcheck disable=SC2034  # these variables are used by the scripts that source this file
# Shared configuration for LinuxGuardian Suite scripts.
# Sourced by every other script in this directory — do not execute directly.

LG_HOME="${LG_HOME:-$HOME/.linuxguardian}"
LG_BASELINE_DIR="$LG_HOME/baselines"
LG_CHECKPOINT_DIR="$LG_HOME/checkpoints"
LG_QUARANTINE_DIR="$LG_HOME/quarantine"
LG_LOG_DIR="$LG_HOME/logs"
LG_INCIDENT_DIR="$LG_HOME/incidents"
LG_SCAN_DIR="$LG_HOME/scans"
LG_CONFIG_FILE="$LG_HOME/config"

# Quick scans skip caches, VCS metadata, and bulky SDKs/toolchains. Override
# in ~/.linuxguardian/config. Full scans only skip /sys /proc /dev.
LG_CLAM_EXCLUDE_DIRS_QUICK='^/sys|^/proc|^/dev|/\.cache($|/)|/\.local/share/Trash|/snap/|/node_modules/|/\.git($|/)|/\.npm($|/)|/\.rustup($|/)|/\.cargo($|/)|/nvidia/nvidia_sdk|/PX4-Autopilot|/STM32Cube($|/)|/st/stm32cubeide|/\.gz($|/)|/Passwords_DO_NOT_OPEN($|/)|/\.linuxguardian/quarantine($|/)|/\.ssh/old_deploy_key|/\.aws/credentials\.bak|/\.env\.production\.bak'
# The honeypot is a decoy whose only job is to be left alone; our own scans must not read it.
LG_CLAM_EXCLUDE_DIRS_FULL='^/sys|^/proc|^/dev|/Passwords_DO_NOT_OPEN($|/)|/\.linuxguardian/quarantine($|/)|/\.ssh/old_deploy_key|/\.aws/credentials\.bak|/\.env\.production\.bak'

LG_MONITORED_DIRS_DEFAULT="$HOME/Documents"
LG_HONEYPOT_DIR="$HOME/Documents/Passwords_DO_NOT_OPEN"

LG_LOG_FILE="$LG_LOG_DIR/linuxguardian.log"

mkdir -p "$LG_BASELINE_DIR" "$LG_CHECKPOINT_DIR" "$LG_QUARANTINE_DIR" \
         "$LG_LOG_DIR" "$LG_INCIDENT_DIR" "$LG_SCAN_DIR" "$LG_SCAN_DIR/history"

# Everything under here (evidence, logs, settings, quarantine) is private to you; a 700 top folder keeps other accounts out of all of it.
chmod 700 "$LG_HOME" 2>/dev/null || true

# Settings you may override in ~/.linuxguardian/config, one per line:  NAME=value  (quotes optional, '#' starts a comment).
# The file is READ, never run: it is data, not a script. Only the names below are accepted, values are taken literally (only $HOME,
# ${HOME} and a leading ~/ are expanded; $(...) and backticks stay plain text), and the file is ignored altogether unless it is a plain
# file you own that other users can't write to. A file that could run code every time any LinuxGuardian script starts would be a
# hiding place for an intruder, and nothing watches it the way shell start-up files are watched.
LG_CONFIG_ALLOWED=" LG_CLAM_EXCLUDE_DIRS_QUICK LG_CLAM_EXCLUDE_DIRS_FULL LG_MONITORED_DIRS_DEFAULT LG_HONEYPOT_DIR "

lg_load_config() {
  local f="$LG_CONFIG_FILE" line name value
  [ -e "$f" ] || [ -L "$f" ] || return 0
  if [ -L "$f" ] || [ ! -f "$f" ] || [ "$(stat -c %u "$f" 2>/dev/null)" != "$(id -u)" ]; then
    echo "[WARN] Ignoring $f: it must be a regular file that you own." >&2
    return 0
  fi
  if [ -n "$(find "$f" -maxdepth 0 -perm /002 2>/dev/null)" ] \
     || { [ "$(stat -c %g "$f" 2>/dev/null)" != "$(id -g)" ] && [ -n "$(find "$f" -maxdepth 0 -perm /020 2>/dev/null)" ]; }; then
    echo "[WARN] Ignoring $f: other users can write to it. Fix with: chmod go-w \"$f\"" >&2
    return 0
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|\#*|[[:space:]]*\#*) continue ;; esac
    if [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Z][A-Z0-9_]*)=(.*)$ ]]; then
      name="${BASH_REMATCH[2]}"
      value="${BASH_REMATCH[3]}"
      case "$LG_CONFIG_ALLOWED" in
        *" $name "*) ;;
        *) echo "[WARN] $f: '$name' can't be set here (allowed:${LG_CONFIG_ALLOWED% })." >&2; continue ;;
      esac
      # shellcheck disable=SC2088  # a literal "~/" prefix is exactly what is being matched below
      case "$value" in
        \'*\') value="${value#\'}"; value="${value%\'}" ;;                               # single quotes: exactly as written
        \"*\") value="${value#\"}"; value="${value%\"}"; value="${value//\$\{HOME\}/$HOME}"; value="${value//\$HOME/$HOME}" ;;
        '~/'*) value="$HOME/${value#\~/}" ;;
        *) value="${value//\$\{HOME\}/$HOME}"; value="${value//\$HOME/$HOME}" ;;
      esac
      printf -v "$name" '%s' "$value"
    else
      echo "[WARN] $f: ignoring a line that isn't NAME=value." >&2
    fi
  done < "$f"
}
lg_load_config

if [ -t 1 ]; then
  LG_C_RED=$'\033[0;31m'
  LG_C_GREEN=$'\033[0;32m'
  LG_C_YELLOW=$'\033[0;33m'
  LG_C_BLUE=$'\033[0;34m'
  LG_C_BOLD=$'\033[1m'
  LG_C_RESET=$'\033[0m'
else
  LG_C_RED="" LG_C_GREEN="" LG_C_YELLOW="" LG_C_BLUE="" LG_C_BOLD="" LG_C_RESET=""
fi

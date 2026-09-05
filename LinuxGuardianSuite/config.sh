#!/usr/bin/env bash
# Shared configuration for LinuxGuardian Suite scripts.
# Sourced by every other script in this directory — do not execute directly.

LG_HOME="${LG_HOME:-$HOME/.linuxguardian}"
LG_BASELINE_DIR="$LG_HOME/baselines"
LG_CHECKPOINT_DIR="$LG_HOME/checkpoints"
LG_QUARANTINE_DIR="$LG_HOME/quarantine"
LG_LOG_DIR="$LG_HOME/logs"
LG_INCIDENT_DIR="$LG_HOME/incidents"
LG_CONFIG_FILE="$LG_HOME/config"

LG_MONITORED_DIRS_DEFAULT="$HOME/Documents"
LG_HONEYPOT_DIR="$HOME/Documents/Passwords_DO_NOT_OPEN"

LG_LOG_FILE="$LG_LOG_DIR/linuxguardian.log"

mkdir -p "$LG_BASELINE_DIR" "$LG_CHECKPOINT_DIR" "$LG_QUARANTINE_DIR" \
         "$LG_LOG_DIR" "$LG_INCIDENT_DIR"

# Allow the user to override any of the above in ~/.linuxguardian/config
# shellcheck source=/dev/null
[ -f "$LG_CONFIG_FILE" ] && source "$LG_CONFIG_FILE"

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

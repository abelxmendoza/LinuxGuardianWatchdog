#!/usr/bin/env bash
# Minimal sanity test: every script parses cleanly and --help works.
set -uo pipefail

SUITE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../LinuxGuardianSuite" &>/dev/null && pwd)"
fail=0

for script in "$SUITE_DIR"/*.sh; do
  name="$(basename "$script")"
  [ "$name" = "config.sh" ] && continue
  [ "$name" = "utils.sh" ] && continue

  if ! bash -n "$script"; then
    echo "SYNTAX ERROR: $name"
    fail=1
    continue
  fi

  if "$script" --help >/dev/null 2>&1; then
    echo "OK: $name --help"
  else
    echo "FAIL: $name --help (exit $?)"
    fail=1
  fi
done

# shellcheck source=../LinuxGuardianSuite/config.sh
source "$SUITE_DIR/config.sh"
# shellcheck source=../LinuxGuardianSuite/utils.sh
source "$SUITE_DIR/utils.sh"

progress_out="$(lg_progress "clamav" "hello" "pct=12" "eta_sec=90")"
expected="LG_PROGRESS|phase=clamav|message=hello|pct=12|eta_sec=90"
if [ "$progress_out" = "$expected" ]; then
  echo "OK: lg_progress"
else
  echo "FAIL: lg_progress ($progress_out)"
  fail=1
fi

if [ "$(lg_fmt_duration 75)" = "1m 15s" ]; then
  echo "OK: lg_fmt_duration"
else
  echo "FAIL: lg_fmt_duration"
  fail=1
fi

# Heartbeat must print LG_PROGRESS while a child is alive, then return.
sleep 2 &
watch_pid=$!
watch_log="$(mktemp)"
lg_watch_pid "$watch_pid" "clamav" "test heartbeat" "" "step=1" "steps=2" >"$watch_log"
if grep -q '^LG_PROGRESS|phase=clamav' "$watch_log"; then
  echo "OK: lg_watch_pid heartbeat"
else
  echo "FAIL: lg_watch_pid produced no LG_PROGRESS"
  fail=1
fi
rm -f "$watch_log"

exit $fail

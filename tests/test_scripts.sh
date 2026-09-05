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

exit $fail

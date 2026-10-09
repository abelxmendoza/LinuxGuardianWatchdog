#!/usr/bin/env bash
# Tests linux_updates.sh end to end against STUB pkexec/apt-get/apt-mark/snap/
# unattended-upgrade/dpkg-query binaries in a temp sandbox. Nothing real is
# installed or held and no password is requested; this proves ordering, scope,
# the release guard, hold handling, and error handling.
#
# Hermetic: apt sources and os-release come from fixtures, never the host's.
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
SCRIPT="${LG_UPDATES_SCRIPT:-$ROOT/LinuxGuardianSuite/linux_updates.sh}"
fail=0

pass() { echo "OK: $1"; }
bad()  { echo "FAIL: $1"; fail=1; }

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
mkdir -p "$SANDBOX/bin" "$SANDBOX/lg" "$SANDBOX/apt-good/sources.list.d" "$SANDBOX/apt-bad/sources.list.d"
export LG_HOME="$SANDBOX/lg"
export STUB_LOG="$SANDBOX/calls.log"

# --- fixtures: a jammy machine whose sources are all jammy, and one with a stray noble source
printf 'VERSION_CODENAME=jammy\nUBUNTU_CODENAME=jammy\n' > "$SANDBOX/os-release"
printf 'deb http://archive.ubuntu.com/ubuntu jammy main\ndeb http://security.ubuntu.com/ubuntu jammy-security main\n' \
  > "$SANDBOX/apt-good/sources.list"
printf 'deb https://pkgs.tailscale.com/stable/ubuntu jammy main\n' > "$SANDBOX/apt-good/sources.list.d/ts.list"
printf 'deb http://archive.ubuntu.com/ubuntu jammy main\n' > "$SANDBOX/apt-bad/sources.list"
printf 'deb http://archive.ubuntu.com/ubuntu noble main\n' > "$SANDBOX/apt-bad/sources.list.d/oops.list"
export LG_OS_RELEASE_FILE="$SANDBOX/os-release"
export LG_APT_ROOT="$SANDBOX/apt-good"

# --- stubs. pkexec just runs its arguments (as the user) so the inner `sh -c`
# --- script exercises the other stubs.
cat > "$SANDBOX/bin/pkexec" <<'EOF'
#!/bin/sh
# Log only the program and flag: $3 is the whole multi-line root script, and
# logging it would make its text look like real apt-get/snap invocations.
printf 'pkexec %s %s\n' "$1" "$2" >> "$STUB_LOG"
[ -n "${STUB_PKEXEC_EXIT:-}" ] && exit "$STUB_PKEXEC_EXIT"
exec "$@"
EOF
cat > "$SANDBOX/bin/apt-get" <<'EOF'
#!/bin/sh
echo "apt-get $*" >> "$STUB_LOG"
case "$*" in
  *"-s upgrade"*)
    # Simulation used by the inventory and the release guard.
    [ -n "${STUB_FOREIGN_PKG:-}" ] && echo "Inst libc6 [2.35-0ubuntu3.8] (2.39-0ubuntu8 Ubuntu:24.04/noble-updates [amd64])"
    exit 0 ;;
  *" upgrade")
    [ -n "${STUB_FAIL_UPGRADE:-}" ] && { echo "E: simulated failure"; exit 100; }
    # Chatty and slow on purpose: lets a test close the reader first, so these
    # writes hit a dead pipe (the SIGPIPE-mid-install scenario).
    sleep 0.3; echo "Unpacking a"; echo "Unpacking b"; echo "Setting up a" ;;
esac
echo "stub apt-get ok"
EOF
cat > "$SANDBOX/bin/snap" <<'EOF'
#!/bin/sh
echo "snap $*" >> "$STUB_LOG"
EOF
cat > "$SANDBOX/bin/unattended-upgrade" <<'EOF'
#!/bin/sh
echo "unattended-upgrade $*" >> "$STUB_LOG"
EOF
# dpkg-query: STUB_INSTALLED is a space-separated list of "installed" packages.
cat > "$SANDBOX/bin/dpkg-query" <<'EOF'
#!/bin/sh
for p in ${STUB_INSTALLED-ros-humble-a ros-humble-b bash}; do printf '%s\tii \n' "$p"; done
EOF
# apt-mark: `showhold` reports STUB_HELD (space-separated); anything else is logged.
cat > "$SANDBOX/bin/apt-mark" <<'EOF'
#!/bin/sh
case "$1" in
  showhold) for p in ${STUB_HELD:-}; do echo "$p"; done; exit 0 ;;
esac
echo "apt-mark $*" >> "$STUB_LOG"
EOF
chmod +x "$SANDBOX"/bin/*

run() { : > "$STUB_LOG"; PATH="$SANDBOX/bin:$PATH" "$SCRIPT" "$@" 2>&1; }

# ===========================================================================
# Installing
# ===========================================================================
# 1. Full apply: update lists, then upgrade, then snap — in that order.
out="$(run --apply)"; rc=$?
calls="$(cat "$STUB_LOG")"
if [ "$rc" -eq 0 ] && grep -q "Update run finished" <<<"$out"; then pass "apply (all) exits 0 and reports success"; else bad "apply (all) rc=$rc out=$out"; fi
order="$(grep -nE '^(apt-get update|apt-get -y .* upgrade|snap refresh)' <<<"$calls" | cut -d: -f2- | tr '\n' '|')"
case "$order" in
  "apt-get update|apt-get -y "*" upgrade|snap refresh|") pass "apply (all) runs update -> upgrade -> snap refresh in order" ;;
  *) bad "apply (all) order wrong: $order" ;;
esac
grep -q '^pkexec /bin/sh -c' <<<"$calls" && pass "privileged work goes through pkexec /bin/sh -c" || bad "pkexec not used"
grep -q 'unattended-upgrade' <<<"$calls" && bad "apply (all) must not call unattended-upgrade" || pass "apply (all) does not use unattended-upgrade"
grep -qE 'full-upgrade|dist-upgrade|autoremove|remove' <<<"$calls" && bad "apply must never remove packages or full-upgrade" || pass "apply never uses full-upgrade/remove/autoremove"

# 2. Security-only: unattended-upgrade, no snap, no blanket apt-get upgrade.
out="$(run --apply --security-only)"; rc=$?
calls="$(cat "$STUB_LOG")"
if [ "$rc" -eq 0 ]; then pass "security-only exits 0"; else bad "security-only rc=$rc"; fi
grep -q '^unattended-upgrade' <<<"$calls" && pass "security-only runs unattended-upgrade" || bad "security-only did not run unattended-upgrade"
grep -q '^snap' <<<"$calls" && bad "security-only must not touch snaps" || pass "security-only leaves snaps alone"
grep -qE '^apt-get -y .* upgrade' <<<"$calls" && bad "security-only must not run a blanket apt-get upgrade" || pass "security-only skips blanket apt-get upgrade"

# 3. Dry run: no privilege escalation, nothing executed.
out="$(run --apply --dry-run --no-snap)"; rc=$?
calls="$(cat "$STUB_LOG")"
if [ "$rc" -eq 0 ]; then pass "dry-run exits 0"; else bad "dry-run rc=$rc"; fi
grep -qE '^(pkexec|snap|unattended-upgrade)|^apt-get (update|-y)' <<<"$calls" && bad "dry-run escalated or installed: $calls" || pass "dry-run never calls pkexec/installers"

# 4. Password prompt dismissed (pkexec exits 127): clean cancel, exit 2.
out="$(STUB_PKEXEC_EXIT=127 run --apply)"; rc=$?
if [ "$rc" -eq 2 ] && grep -qi "cancelled" <<<"$out"; then pass "dismissed prompt -> exit 2 with a clear message"; else bad "dismissed prompt rc=$rc out=$out"; fi
grep -q '^apt-get update' "$STUB_LOG" && bad "installers ran despite cancelled prompt" || pass "nothing runs when the prompt is cancelled"

# 5. A failing upgrade is reported, not swallowed.
out="$(STUB_FAIL_UPGRADE=1 run --apply)"; rc=$?
if [ "$rc" -eq 1 ] && grep -qi "finished with errors" <<<"$out"; then pass "failed upgrade -> exit 1 with error message"; else bad "failed upgrade rc=$rc"; fi
grep -q '^snap refresh' "$STUB_LOG" && pass "snap still refreshed after an apt failure (independent steps)" || bad "snap skipped after apt failure"

# 5b. Closing the GUI mid-install must not abort the install. `head -n 1` exits
#     immediately, so everything the root side prints afterwards hits a closed
#     pipe; without protection apt/dpkg would die of SIGPIPE half-way through.
: > "$STUB_LOG"
rm -rf "$LG_HOME/incidents"
PATH="$SANDBOX/bin:$PATH" "$SCRIPT" --apply 2>&1 | head -n 1 >/dev/null
calls="$(cat "$STUB_LOG")"
if grep -q '^snap refresh' <<<"$calls" && grep -qE '^apt-get -y .* upgrade' <<<"$calls"; then
  pass "install runs to completion even if the reader of its output disappears"
else
  bad "install was cut short when the output reader closed: $(tr '\n' '|' <<<"$calls")"
fi
if grep -rq "Installed all updates" "$LG_HOME/incidents" 2>/dev/null; then
  pass "result is still recorded after the reader disappears"
else
  bad "no incident recorded after the reader disappeared"
fi
if grep -q "Setting up a" "$LG_HOME"/logs/updates/apply-*.log 2>/dev/null; then
  pass "output keeps being written to the log after the reader disappears"
else
  bad "log is missing output produced after the reader disappeared"
fi

# ===========================================================================
# Release guard: never install if anything is for a different release
# ===========================================================================
for args in "--apply" "--apply --security-only" "--apply --dry-run"; do
  # shellcheck disable=SC2086
  out="$(LG_APT_ROOT="$SANDBOX/apt-bad" run $args)"; rc=$?
  calls="$(cat "$STUB_LOG")"
  if [ "$rc" -eq 3 ]; then pass "guard: '$args' exits 3 when a source is for another release"; else bad "guard: '$args' rc=$rc"; fi
  grep -q "Refusing to install" <<<"$out" && grep -q "noble" <<<"$out" \
    && pass "guard: '$args' says why (names the foreign release)" || bad "guard: '$args' gave no reason: $out"
  grep -qE '^(pkexec|snap|unattended-upgrade)|^apt-get (update|-y)' <<<"$calls" \
    && bad "guard: '$args' still escalated/installed: $calls" || pass "guard: '$args' never reaches pkexec or any installer"
done

# A pending package that would come from another release blocks too, even
# though every source file looks fine.
out="$(STUB_FOREIGN_PKG=1 run --apply)"; rc=$?
if [ "$rc" -eq 3 ] && grep -q "libc6" <<<"$out" && grep -q "noble-updates" <<<"$out"; then
  pass "guard: a pending package from another release blocks installing"
else
  bad "guard: foreign pending package rc=$rc out=$out"
fi
grep -q '^pkexec' "$STUB_LOG" && bad "guard: foreign package still escalated" || pass "guard: foreign package never reaches pkexec"

# Unknown release => fail closed.
out="$(LG_OS_RELEASE_FILE="$SANDBOX/missing" run --apply)"; rc=$?
if [ "$rc" -eq 3 ]; then pass "guard: fails closed when the running release can't be determined"; else bad "guard: unknown release rc=$rc"; fi

# ===========================================================================
# Pinned stacks (apt-mark hold)
# ===========================================================================
out="$(run --hold ros2)"; rc=$?
calls="$(cat "$STUB_LOG")"
if [ "$rc" -eq 0 ]; then pass "hold: exits 0"; else bad "hold: rc=$rc out=$out"; fi
grep -q '^pkexec /bin/sh -c' <<<"$calls" && pass "hold: goes through pkexec" || bad "hold: pkexec not used"
if [ "$(grep '^apt-mark' <<<"$calls")" = "apt-mark hold ros-humble-a ros-humble-b" ]; then
  pass "hold: holds exactly the installed ROS packages and nothing else (not 'bash')"
else
  bad "hold: wrong apt-mark call: $(grep '^apt-mark' <<<"$calls")"
fi

# Only what is held gets released.
out="$(STUB_HELD="ros-humble-a" run --unhold ros2)"; rc=$?
calls="$(cat "$STUB_LOG")"
if [ "$rc" -eq 0 ] && [ "$(grep '^apt-mark' <<<"$calls")" = "apt-mark unhold ros-humble-a" ]; then
  pass "unhold: releases only the packages that are actually held"
else
  bad "unhold: rc=$rc call=$(grep '^apt-mark' <<<"$calls")"
fi

# Already in the requested state: no password prompt at all.
out="$(STUB_HELD="ros-humble-a ros-humble-b" run --hold ros2)"; rc=$?
if [ "$rc" -eq 0 ] && grep -q "Nothing to hold" <<<"$out" && ! grep -q '^pkexec' "$STUB_LOG"; then
  pass "hold: already-held stack needs no password prompt"
else
  bad "hold: no-op case rc=$rc out=$out"
fi

# Names that aren't valid package names never reach apt-mark.
out="$(STUB_INSTALLED='ros-humble-ok ros-humble-BAD ros-humble-x;y' run --hold ros2)"; rc=$?
calls="$(cat "$STUB_LOG")"
if [ "$(grep '^apt-mark' <<<"$calls")" = "apt-mark hold ros-humble-ok" ]; then
  pass "hold: invalid package names are dropped before root is involved"
else
  bad "hold: invalid names leaked: $(grep '^apt-mark' <<<"$calls")"
fi

out="$(STUB_PKEXEC_EXIT=126 run --hold nvidia)"; rc=$?
if [ "$rc" -eq 2 ] || grep -q "Nothing to hold" <<<"$out"; then pass "hold: cancelled prompt is handled (exit 2) / nothing to do"; else bad "hold: cancel rc=$rc out=$out"; fi

out="$(run --hold bogus)"; rc=$?
if [ "$rc" -eq 1 ] && grep -q "Unknown stack" <<<"$out" && ! grep -q '^pkexec' "$STUB_LOG"; then
  pass "hold: unknown stack is rejected without prompting"
else
  bad "hold: unknown stack rc=$rc out=$out"
fi

# ===========================================================================
# What runs as root
# ===========================================================================
extract() { sed -n "/^$1='/,/^'\$/p" "$SCRIPT" | sed "1s/^$1='//;\$d"; }

# 6. The install scripts stay fixed strings: no variable/command expansion
#    other than the script's own $rc / $?.
audit() {  # audit NAME ALLOWED_REGEX
  local text stripped
  text="$(extract "$1")"
  if [ -z "$text" ]; then bad "could not extract $1 to audit"; return; fi
  stripped="$(sed -E "s/$2//g" <<<"$text")"
  if grep -qE '\$[A-Za-z_{(@#?!*0-9]|`' <<<"$stripped"; then
    bad "$1 contains an unexpected expansion: $(grep -nE '\$[A-Za-z_{(@#?!*0-9]|`' <<<"$stripped" | head -3)"
  else
    pass "$1 is a fixed string (no unexpected interpolation)"
  fi
}
audit PRIV_SCRIPT_ALL '\$rc|\$\?'
audit PRIV_SCRIPT_SECURITY '\$rc|\$\?'
# The hold script may only reference its own positional arguments and loop var.
audit PRIV_SCRIPT_MARK '\$1|\$#|"\$@"|\$act|"\$p"|\$p'

# 7. The root-side hold script validates its own input — run it directly, with
#    hostile arguments, exactly as pkexec would invoke it.
mark="$(extract PRIV_SCRIPT_MARK)"
mark_run() { : > "$STUB_LOG"; PATH="$SANDBOX/bin:$PATH" /bin/sh -c "$mark" sh "$@" 2>&1; }

mark_run hold good-pkg libstdc++6 "pkg:i386" >/dev/null; rc=$?
if [ "$rc" -eq 0 ] && grep -qx "apt-mark hold good-pkg libstdc++6 pkg:i386" "$STUB_LOG"; then
  pass "root script: valid names reach apt-mark"
else
  bad "root script: valid call rc=$rc log=$(cat "$STUB_LOG")"
fi
for evil in "-oops" "--force" "UPPER" "a;b" 'x$(id)' 'a`b`' "a b" "x|y" "../etc"; do
  mark_run hold fine-pkg "$evil" >/dev/null; rc=$?
  if [ "$rc" -eq 2 ] && ! grep -q '^apt-mark' "$STUB_LOG"; then
    pass "root script: rejects hostile name '$evil' and runs nothing"
  else
    bad "root script: accepted '$evil' (rc=$rc, log=$(cat "$STUB_LOG"))"
  fi
done
mark_run purge some-pkg >/dev/null; rc=$?
if [ "$rc" -eq 2 ] && ! grep -q '^apt-mark' "$STUB_LOG"; then pass "root script: only hold/unhold actions are allowed"; else bad "root script: allowed action 'purge' rc=$rc"; fi
mark_run hold >/dev/null; rc=$?
if [ "$rc" -eq 2 ] && ! grep -q '^apt-mark' "$STUB_LOG"; then pass "root script: refuses an empty package list"; else bad "root script: empty list rc=$rc"; fi

exit $fail

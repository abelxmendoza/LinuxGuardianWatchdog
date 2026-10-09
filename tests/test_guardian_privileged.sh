#!/usr/bin/env bash
# The two root actions in linux_guardian.sh (definitions update, rootkit check) and the
# honest bookkeeping around them. Everything runs in a sandbox with stub binaries:
# the real pkexec/freshclam/rkhunter/clamscan are never touched.
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
GUARD="${LG_GUARDIAN:-$ROOT/LinuxGuardianSuite/linux_guardian.sh}"
SAMPLE="$ROOT/LinuxGuardianSuiteUI/tests/clamscan-sample.log"
fail=0
pass() { echo "OK: $1"; }
bad()  { echo "FAIL: $1"; fail=1; }

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
mkdir -p "$SANDBOX/bin" "$SANDBOX/target"
echo hello > "$SANDBOX/target/file.txt"
export LG_HOME="$SANDBOX/lg" CALLS="$SANDBOX/calls"

# pkexec: records exactly what it was asked to run as root, then runs it (or plays "prompt dismissed").
cat > "$SANDBOX/bin/pkexec" <<'STUB'
#!/bin/sh
printf 'pkexec:%s\n' "$*" >> "$CALLS"
[ "${STUB_PKEXEC:-}" = "cancel" ] && exit 126
exec "$@"
STUB
cat > "$SANDBOX/bin/freshclam" <<'STUB'
#!/bin/sh
echo "freshclam $*" >> "$CALLS"
case "${STUB_FRESHCLAM:-ok}" in
  locked) echo "ERROR: /var/log/clamav/freshclam.log is locked by another process"; exit 62 ;;
esac
echo "daily.cld updated (version: 27000)"
STUB
cat > "$SANDBOX/bin/rkhunter" <<'STUB'
#!/bin/sh
echo "rkhunter $*" >> "$CALLS"
echo "[ Rootkit Hunter version 1.4.6 ]"
i=0; while [ $i -lt 20 ]; do echo "  Checking file properties of /usr/bin/tool$i                 [ OK ]"; i=$((i+1)); done
if [ "${STUB_RK_WARN:-}" = "props" ]; then
  echo "  Warning: The file properties have changed:"
  echo "  Warning: The file properties have changed:"
elif [ "${STUB_RK_WARN:-}" = "mixed" ]; then
  echo "  Warning: The file properties have changed:"
  echo "  Warning: Hidden file found: /usr/bin/.sneaky"
fi
echo "Rootkit checks..."; echo "    Rootkits checked : 497"; echo "    Possible rootkits: 0"
echo "System checks summary"; echo "====================="
STUB
cat > "$SANDBOX/bin/clamscan" <<STUB
#!/bin/sh
[ "\$1" = "--help" ] && { echo "  --progress"; exit 0; }
cat "$SAMPLE"
STUB
printf '#!/bin/sh\nexit 1\n' > "$SANDBOX/bin/clamdscan"
# systemctl: `cat` succeeds unless STUB_NO_UNIT; enable/is-enabled/is-active are logged/answered.
cat > "$SANDBOX/bin/systemctl" <<'STUB'
#!/bin/sh
echo "systemctl $*" >> "$CALLS"
case "$1" in
  cat) [ -z "${STUB_NO_UNIT:-}" ] ;;
  is-enabled) echo disabled; exit 1 ;;
  is-active) echo inactive; exit 3 ;;
  enable) exit 0 ;;
esac
STUB
# dpkg: owns /usr/bin/curl and /usr/bin/awk; --verify reports nothing, or STUB_MODIFIED.
cat > "$SANDBOX/bin/dpkg" <<'STUB'
#!/bin/sh
if [ "$1" = "-S" ]; then
  shift; shift   # -S --
  rc=0
  for p in "$@"; do
    case "$p" in
      /usr/bin/curl) echo "curl: $p" ;;
      /usr/bin/awk) echo "mawk: $p" ;;
      *) echo "dpkg-query: no path found matching pattern $p" >&2; rc=1 ;;
    esac
  done
  exit $rc
fi
[ "$1" = "--verify" ] && { [ -n "${STUB_MODIFIED:-}" ] && echo "??5??????   $STUB_MODIFIED"; exit 0; }
STUB
chmod +x "$SANDBOX/bin"/*

guard() { PATH="$SANDBOX/bin:$PATH" bash "$GUARD" "$@" 2>&1; }
last() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get(sys.argv[2], "<absent>"))' "$LG_HOME/scans/last.json" "$1"; }
reset() { rm -rf "$LG_HOME" "$CALLS"; unset STUB_PKEXEC STUB_FRESHCLAM STUB_RK_WARN STUB_NO_UNIT STUB_MODIFIED; }
called() { grep -q -- "$1" "$CALLS" 2>/dev/null; }

# ---------------------------------------------------------------- definitions update
reset
out="$(guard --update)"; rc=$?
[ "$rc" -eq 0 ] && pass "--update succeeds" || bad "--update rc=$rc: $out"
called '^pkexec:/bin/sh -c echo "Running freshclam as root..."; exec freshclam sh$' && pass "freshclam goes through pkexec with the fixed script" || bad "pkexec call wrong: $(cat "$CALLS" 2>/dev/null)"
called '^freshclam' && pass "freshclam was run" || bad "freshclam never ran"
called 'rkhunter' && bad "--update must never touch rkhunter (--update is dead on Ubuntu, --propupd blesses the current state)" || pass "--update does not touch rkhunter"
echo "$out" | grep -q "up to date" && pass "--update reports success" || bad "no success message: $out"
ls "$LG_HOME/logs"/freshclam-*.log >/dev/null 2>&1 && pass "update output is logged" || bad "no freshclam log"

reset; export STUB_PKEXEC=cancel
out="$(guard --update)"; rc=$?
[ "$rc" -eq 2 ] && pass "dismissed password prompt exits 2 (cancelled)" || bad "cancel rc=$rc"
called '^freshclam' && bad "freshclam ran despite cancel" || pass "nothing ran after cancel"
echo "$out" | grep -qi "nothing was changed" && pass "cancel is explained" || bad "no cancel message: $out"

reset; export STUB_FRESHCLAM=locked
out="$(guard --update)"; rc=$?
[ "$rc" -eq 1 ] && echo "$out" | grep -qi "already running" && pass "locked freshclam gets a plain explanation" || bad "locked: rc=$rc out=$out"

# ------------------------------------------------- automatic definition updates
reset
out="$(guard --enable-auto-update)"; rc=$?
[ "$rc" -eq 0 ] && pass "--enable-auto-update succeeds" || bad "rc=$rc: $out"
called '^pkexec:/bin/sh -c exec systemctl enable --now clamav-freshclam sh$' && pass "enables exactly the clamav-freshclam service via pkexec" || bad "wrong call: $(cat "$CALLS" 2>/dev/null)"
grep -E '^systemctl (disable|mask|stop|restart)' "$CALLS" >/dev/null 2>&1 && bad "touched other service state" || pass "does nothing but enable that one unit"

reset; export STUB_PKEXEC=cancel
out="$(guard --enable-auto-update)"; rc=$?
[ "$rc" -eq 2 ] && pass "dismissed prompt exits 2 and changes nothing" || bad "cancel rc=$rc"
called '^systemctl enable' && bad "enabled despite cancel" || pass "nothing enabled after cancel"

reset; export STUB_NO_UNIT=1
out="$(guard --enable-auto-update)"; rc=$?
[ "$rc" -eq 1 ] && ! called pkexec && echo "$out" | grep -q "apt install clamav-freshclam" && pass "missing service: no prompt, says how to install it" || bad "no-unit: rc=$rc out=$out"

# ------------------------------------------------------------------- rootkit check
RK_SCRIPT='exec rkhunter --check --sk --nocolors --no-mail-on-warning'
reset
out="$(guard --scan --rootkit "$SANDBOX/target")"; rc=$?
[ "$rc" -eq 0 ] && pass "--scan --rootkit completes" || bad "scan rc=$rc: $out"
called "^pkexec:/bin/sh -c $RK_SCRIPT sh\$" && pass "rkhunter runs as root through pkexec with the fixed command" || bad "rkhunter call wrong: $(cat "$CALLS" 2>/dev/null)"
called '^rkhunter --check --sk --nocolors --no-mail-on-warning$' && pass "rkhunter got exactly the expected arguments" || bad "rkhunter args wrong"
[ "$(last rootkit_check)" = "ran" ] && pass "saved as rootkit_check=ran" || bad "rootkit_check=$(last rootkit_check)"
[ "$(last rkhunter_warnings)" = "0" ] && pass "zero warnings recorded for a clean run" || bad "warnings=$(last rkhunter_warnings)"
grep -qE 'propupd|rkhunter --update' "$CALLS" 2>/dev/null && bad "rkhunter baseline/update must never be automated" || pass "no --propupd / --update anywhere"

reset
out="$(guard --scan "$SANDBOX/target")"; rc=$?
called 'pkexec' && bad "a password prompt appeared without --rootkit" || pass "no password prompt unless --rootkit"
called 'rkhunter' && bad "rkhunter ran without --rootkit" || pass "rkhunter not run without --rootkit"
[ "$(last rootkit_check)" = "needs_root" ] && pass "saved as needs_root, not Clean" || bad "rootkit_check=$(last rootkit_check)"
[ "$(last rkhunter_warnings)" = "<absent>" ] && pass "no fake '0 warnings' for a check that never ran" || bad "warnings recorded: $(last rkhunter_warnings)"
echo "$out" | grep -q -- "--rootkit" && pass "tells the user how to opt in" || bad "no hint about --rootkit"

reset; export STUB_PKEXEC=cancel
out="$(guard --scan --rootkit "$SANDBOX/target")"; rc=$?
[ "$rc" -eq 0 ] && pass "a dismissed prompt doesn't fail the whole scan" || bad "scan rc=$rc"
[ "$(last rootkit_check)" = "cancelled" ] && pass "saved as cancelled" || bad "rootkit_check=$(last rootkit_check)"
called '^rkhunter' && bad "rkhunter ran despite cancel" || pass "rkhunter did not run after cancel"
[ "$(last files)" != "<absent>" ] && pass "the ClamAV half of the scan is still saved" || bad "scan not saved"

reset; export STUB_RK_WARN=props
out="$(guard --scan --rootkit "$SANDBOX/target")"
[ "$(last rkhunter_warnings)" = "2" ] && [ "$(last rkhunter_property_changes)" = "2" ] && pass "changed-file warnings are counted separately" || bad "warnings=$(last rkhunter_warnings) props=$(last rkhunter_property_changes)"
echo "$out" | grep -q -- "--refresh-rootkit-baseline" && echo "$out" | grep -qi "checked against its Ubuntu package" && pass "explains the baseline and points at the gated refresh" || bad "no baseline explanation: $out"
called 'propupd' && bad "propupd was executed" || pass "a scan never refreshes the baseline by itself"

reset; export STUB_RK_WARN=mixed
guard --scan --rootkit "$SANDBOX/target" >/dev/null
[ "$(last rkhunter_warnings)" = "2" ] && [ "$(last rkhunter_property_changes)" = "1" ] && pass "a real warning isn't hidden among changed-file ones" || bad "warnings=$(last rkhunter_warnings) props=$(last rkhunter_property_changes)"

# ------------------------------------------------------ rootkit baseline refresh
mklast() {  # mklast "path1 path2 ..."  -> a rootkit log with those files flagged, and last.json pointing at it
  mkdir -p "$LG_HOME/scans"
  { echo "[ Rootkit Hunter version 1.4.6 ]"; i=0; while [ $i -lt 20 ]; do echo "  Checking something $i      [ OK ]"; i=$((i+1)); done
    for f in $1; do echo "    $f                       [ Warning ]"; done
    echo "File properties checks..."; echo "    Suspect files: $(echo $1 | wc -w)"; echo "    Possible rootkits: 0"
    echo "One or more warnings have been found while checking the system."; } > "$LG_HOME/scans/rk.log"
  printf '{"rk_report": "%s", "rootkit_check": "ran"}' "$LG_HOME/scans/rk.log" > "$LG_HOME/scans/last.json"
}
reset; mklast "/usr/bin/curl /usr/bin/awk"
out="$(guard --refresh-rootkit-baseline)"; rc=$?
[ "$rc" -eq 0 ] && called '^pkexec:/bin/sh -c exec rkhunter --propupd sh$' && pass "all changes explained by packages: baseline refreshed via pkexec" || bad "refresh: rc=$rc out=$out calls=$(cat "$CALLS" 2>/dev/null)"
called '^rkhunter --propupd$' && pass "rkhunter got exactly --propupd" || bad "rkhunter args"

reset; mklast "/usr/bin/curl /usr/local/bin/implant"
out="$(guard --refresh-rootkit-baseline)"; rc=$?
[ "$rc" -eq 3 ] && pass "an unexplained file blocks the refresh (exit 3)" || bad "unexplained: rc=$rc"
called 'pkexec' && bad "asked for a password even though it was unsafe" || pass "no password prompt, nothing run, when blocked"
echo "$out" | grep -q "implant" && pass "the blocking file is named" || bad "blocking file not shown: $out"

reset; mklast "/usr/bin/curl"; export STUB_MODIFIED="/usr/bin/curl"
guard --refresh-rootkit-baseline >/dev/null; rc=$?
[ "$rc" -eq 3 ] && ! called pkexec && pass "a file that differs from its package blocks the refresh" || bad "modified: rc=$rc"

reset; mklast "/usr/bin/curl"; export STUB_PKEXEC=cancel
guard --refresh-rootkit-baseline >/dev/null; rc=$?
[ "$rc" -eq 2 ] && ! called '^rkhunter' && pass "dismissed prompt: exit 2, baseline untouched" || bad "cancel: rc=$rc"

reset
guard --refresh-rootkit-baseline >/dev/null; rc=$?
[ "$rc" -eq 3 ] && ! called pkexec && pass "no scan on file: refuses" || bad "no scan: rc=$rc"

# -------------------------------------------- what runs as root is fixed text
for name in PRIV_SCRIPT_FRESHCLAM PRIV_SCRIPT_RKHUNTER PRIV_SCRIPT_ENABLE_FRESHCLAM PRIV_SCRIPT_PROPUPD; do
  line="$(grep "^$name='" "$GUARD")"
  if [ -z "$line" ]; then bad "$name not found as a single-quoted constant"; continue; fi
  body="${line#*=}"
  case "$body" in
    *'$'*|*'`'*) bad "$name contains interpolation: $body" ;;
    *) pass "$name is fixed text (no \$ or backticks)" ;;
  esac
  echo "$body" | grep -qE 'sudo|--update|rm |curl|wget|disable|mask' && bad "$name does something unexpected: $body" || pass "$name does only its one job"
done

# ---------------------------------------------------------------------- health / usage
reset
mkdir -p "$SANDBOX/clam"; touch "$SANDBOX/clam/daily.cld"
out="$(LG_CLAMAV_DIR="$SANDBOX/clam" LG_RKHUNTER_DB="$SANDBOX/none.dat" guard --health)"; rc=$?
[ "$rc" -eq 0 ] && echo "$out" | grep -q "Virus definitions: Updated" && pass "--health reports definitions" || bad "--health: rc=$rc out=$out"
guard --help | grep -q 'set -uo\|SCRIPT_DIR\|lg_' && bad "help leaks code/comments from the body" || pass "--help output is the header only"
[ "$(guard --help | wc -l)" -lt 30 ] && pass "--help is short" || bad "--help too long"

echo
[ "$fail" -eq 0 ] && echo "all privileged-scanner checks passed" || echo "SOME CHECKS FAILED"
exit "$fail"

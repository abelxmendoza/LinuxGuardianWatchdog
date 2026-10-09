#!/usr/bin/env bash
# linux_ros_firewall.sh end to end with a stub ufw/pkexec: what reaches root, and what must never.
set -uo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
SCRIPT="${LG_ROSFW:-$ROOT/LinuxGuardianSuite/linux_ros_firewall.sh}"
fail=0
pass() { echo "OK: $1"; }
bad()  { echo "FAIL: $1"; fail=1; }

SB="$(mktemp -d)"; trap 'rm -rf "$SB"' EXIT
mkdir -p "$SB/bin" "$SB/lg" "$SB/home"
export LG_HOME="$SB/lg" CALLS="$SB/calls" LG_ROS_HOME="$SB/home" LG_ROS_OPT="$SB/opt" LG_UFW_CONF="$SB/ufw.conf"
printf 'ENABLED=yes\n' > "$SB/ufw.conf"
echo 'export ROS_DOMAIN_ID=42' > "$SB/home/.bashrc"

cat > "$SB/bin/systemctl" <<'STUB'
#!/bin/sh
[ "$1" = "is-active" ] || exit 1
[ "$2" = "--quiet" ] && unit="$3" || unit="$2"
for u in ${STUB_ACTIVE:-ufw}; do [ "$u" = "$unit" ] && exit 0; done
exit 3
STUB
cat > "$SB/bin/pkexec" <<'STUB'
#!/bin/sh
printf 'pkexec:%s\n' "$*" >> "$CALLS"
[ "${STUB_PKEXEC:-}" = "cancel" ] && exit 126
exec "$@"
STUB
cat > "$SB/bin/ufw" <<'STUB'
#!/bin/sh
echo "ufw $*" >> "$CALLS"
echo "Rule added"
STUB
chmod +x "$SB/bin"/*
run() { PATH="$SB/bin:/usr/bin:/bin" bash "$SCRIPT" "$@" 2>&1; }
reset() { rm -f "$CALLS"; unset STUB_PKEXEC STUB_ACTIVE; }
called() { grep -q -- "$1" "$CALLS" 2>/dev/null; }

reset
out="$(run --plan --peer 192.168.1.50 --preset mavlink)"; rc=$?
[ "$rc" -eq 0 ] && echo "$out" | grep -q "17900:18149" && echo "$out" | grep -q "ONLY 192.168.1.50" && pass "plan shows the domain-42 range and who it applies to" || bad "plan: rc=$rc $out"
[ ! -e "$CALLS" ] && pass "plan runs nothing" || bad "plan ran: $(cat "$CALLS")"

reset
out="$(run --apply --peer 192.168.1.50 --preset mavlink)"; rc=$?
[ "$rc" -eq 0 ] && pass "apply succeeds" || bad "apply rc=$rc: $out"
[ "$(grep -c '^pkexec:' "$CALLS")" -eq 1 ] && pass "one password prompt for all rules" || bad "pkexec calls: $(grep -c '^pkexec:' "$CALLS")"
called "^ufw allow from 192.168.1.50 to any port 17900:18149 proto udp comment LinuxGuardian ROS dds$" && pass "DDS rule: only the robot, only domain 42's ports" || bad "dds rule: $(grep '^ufw' "$CALLS")"
called "^ufw allow from 192.168.1.50 to any port 14540,14550 proto udp comment LinuxGuardian ROS mavlink$" && pass "MAVLink rule added exactly" || bad "mavlink rule"
grep -E '^ufw (enable|disable|default|reset|--force|delete)' "$CALLS" >/dev/null && bad "touched policy/enable state" || pass "never changes the default policy or enables/disables ufw"
grep -q 'anywhere\|0.0.0.0' "$CALLS" && bad "an open-to-all rule was added" || pass "no rule opens anything to everyone"

reset
run --remove --peer 192.168.1.50 >/dev/null; rc=$?
[ "$rc" -eq 0 ] && called "^ufw delete allow from 192.168.1.50 to any port 17900:18149 proto udp$" && pass "remove deletes exactly the same rule" || bad "remove rc=$rc: $(grep '^ufw' "$CALLS")"

reset; export STUB_ACTIVE=none
out="$(run --apply --peer 192.168.1.50)"; rc=$?
[ "$rc" -eq 3 ] && ! called pkexec && echo "$out" | grep -q "not the active firewall" && pass "no active ufw: refuses before any prompt" || bad "no ufw: rc=$rc $out"

reset; export STUB_PKEXEC=cancel
run --apply --peer 192.168.1.50 >/dev/null; rc=$?
[ "$rc" -eq 2 ] && ! called '^ufw' && pass "dismissed prompt: exit 2, no rule added" || bad "cancel rc=$rc"

reset
for evil in any 0.0.0.0/0 10.0.0.0/8 '1.2.3.4; reboot' '$(reboot)' '-h' ''; do
  out="$(run --apply --peer "$evil")"; rc=$?
  if [ "$rc" -ne 0 ] && ! called pkexec && ! called '^ufw'; then pass "refused dangerous peer '$evil'"; else bad "peer '$evil' got through: rc=$rc"; fi
  reset
done
out="$(run --apply --peer 192.168.1.50 --preset 'ssh; reboot')"; rc=$?
[ "$rc" -ne 0 ] && ! called pkexec && pass "unknown preset refused" || bad "bad preset: rc=$rc"

# The root script alone must still refuse tampered rules.
script="$(awk "index(\$0, \"PRIV_SCRIPT_UFW_RULES=\")==1{f=1; sub(/^PRIV_SCRIPT_UFW_RULES='/, \"\")} f{print} f && /^'\$/ {exit}" "$SCRIPT" | sed '$d')"
for tampered in "add dds udp 7400:7649 1.2.3.4;reboot" "add dds udp 7400;7649 1.2.3.4" "add evil udp 7400 1.2.3.4" "add dds sctp 7400 1.2.3.4" "add dds udp 7400 -h" "flush dds udp 7400 1.2.3.4" "add dds udp 7400"; do
  reset
  # shellcheck disable=SC2086
  PATH="$SB/bin:/usr/bin:/bin" sh -c "$script" sh $tampered >/dev/null 2>&1; rc=$?
  if [ "$rc" -ne 0 ] && ! called '^ufw'; then pass "root script refuses: $tampered"; else bad "root script accepted: $tampered (rc=$rc)"; fi
done
reset
PATH="$SB/bin:/usr/bin:/bin" sh -c "$script" sh add dds udp 7400:7649 1.2.3.4 evil udp 7400 1.2.3.4 >/dev/null 2>&1
! called '^ufw' && pass "one bad rule in a group stops ALL of them (validated before any is applied)" || bad "partial application"

if grep -qE '`|\$\([^(]|eval|sudo|ufw (enable|disable|default|reset)' <<<"$script"; then bad "root script contains something it should not"; else pass "root script is plain fixed text"; fi

echo; [ "$fail" -eq 0 ] && echo "all ROS firewall checks passed" || echo "SOME CHECKS FAILED"; exit "$fail"

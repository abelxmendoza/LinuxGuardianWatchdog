#!/usr/bin/env bash
# linux_firewall.sh end to end with a stub ufw/pkexec/systemctl: what reaches root, and what must never.
set -uo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
SCRIPT="${LG_FIREWALL:-$ROOT/LinuxGuardianSuite/linux_firewall.sh}"
fail=0
pass() { echo "OK: $1"; }
bad()  { echo "FAIL: $1"; fail=1; }

SB="$(mktemp -d)"; trap 'rm -rf "$SB"' EXIT
mkdir -p "$SB/bin" "$SB/lg"
export LG_HOME="$SB/lg" CALLS="$SB/calls" LG_UFW_CONF="$SB/ufw.conf" LG_UFW_DEFAULT="$SB/default" LG_UFW_LOG="$SB/ufw.log"
printf 'ENABLED=yes\nLOGLEVEL=low\n' > "$SB/ufw.conf"
printf 'DEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n' > "$SB/default"

cat > "$SB/bin/systemctl" <<'STUB'
#!/bin/sh
if [ "$1" = "restart" ]; then echo "systemctl $*" >> "$CALLS"; exit "${STUB_RESTART_RC:-0}"; fi
[ "$1" = "is-active" ] || exit 1
[ "$2" = "--quiet" ] && unit="$3" || { unit="$2"; }
for u in ${STUB_ACTIVE:-ufw}; do
  if [ "$u" = "$unit" ]; then [ "$2" = "--quiet" ] || echo active; exit 0; fi
done
[ "$2" = "--quiet" ] || echo inactive
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
if [ "$1 $2" = "status numbered" ]; then
  echo "Status: active"
  echo
  echo "     To                         Action      From"
  echo "     --                         ------      ----"
  echo "[ 1] 22/tcp                     ALLOW IN    192.168.1.0/24             # LinuxGuardian: ssh"
  echo "[ 2] 80/tcp                     ALLOW IN    Anywhere                   "
  exit 0
fi
echo "ufw $*" >> "$CALLS"
echo "ok"
STUB
chmod +x "$SB/bin"/*
run() { PATH="$SB/bin:/usr/bin:/bin" bash "$SCRIPT" "$@" 2>&1; }
reset() { rm -f "$CALLS"; unset STUB_PKEXEC STUB_ACTIVE STUB_RESTART_RC; }
called() { grep -q -- "$1" "$CALLS" 2>/dev/null; }
fp() { printf '%s' "$1" | sha256sum | cut -c1-64; }
RULE2="[ 2] 80/tcp                     ALLOW IN    Anywhere"

# ---------------------------------------------------------------- reading needs nothing
reset
out="$(run --status --json)"; rc=$?
[ "$rc" -eq 0 ] && echo "$out" | grep -q '"headline": "Firewall is ON."' && echo "$out" | grep -q '"incoming": "deny"' \
  && pass "status reads on/off and defaults" || bad "status: rc=$rc $out"
out="$(run --plan-add --action allow --port 8080 --from 192.168.1.50)"; rc=$?
[ "$rc" -eq 0 ] && echo "$out" | grep -q "sudo ufw allow proto tcp from 192.168.1.50 to any port 8080 comment LinuxGuardian" \
  && pass "plan shows the exact command" || bad "plan: rc=$rc $out"
[ ! -e "$CALLS" ] && pass "status and plan never touch root or ufw" || bad "read-only ran: $(cat "$CALLS")"

# ---------------------------------------------------------------- rules (read-only, one prompt)
reset
out="$(run --rules)"; rc=$?
[ "$rc" -eq 0 ] && echo "$out" | grep -q "LG_RULES_BEGIN" && echo "$out" | grep -q "LinuxGuardian: ssh" \
  && [ "$(grep -c '^pkexec:' "$CALLS")" -eq 1 ] && ! called '^ufw' && pass "rules: one prompt, nothing changed" || bad "rules: rc=$rc $out"
ls "$LG_HOME"/incidents/*.json >/dev/null 2>&1 && bad "reading rules recorded an event" || pass "reading rules records no event"

# ---------------------------------------------------------------- changes
reset
out="$(run --add --action limit --port 22 --from 192.168.1.0/24 --label 'home ssh')"; rc=$?
[ "$rc" -eq 0 ] && called "^ufw limit proto tcp from 192.168.1.0/24 to any port 22 comment LinuxGuardian: home ssh$" \
  && pass "add: exactly the planned rule" || bad "add: rc=$rc $(cat "$CALLS" 2>/dev/null) $out"
echo "$out" | grep -q "LG_RULES_END" && pass "rules are read back after a change" || bad "no rules after add"
grep -q "Firewall rule added" "$LG_HOME"/incidents/*.json 2>/dev/null && pass "the change is recorded as an event" || bad "no event recorded"
python3 -c "import json;d=json.load(open('$LG_HOME/state/system_changes.json'));assert 'sudo ufw delete limit proto tcp from 192.168.1.0/24 to any port 22' in d[-1]['undo']" 2>/dev/null \
  && pass "the change and how to undo it are in the login-watch ledger" || bad "ledger: $(cat "$LG_HOME/state/system_changes.json" 2>&1)"
grep -E '^ufw (enable|disable|default|reset|--force)' "$CALLS" >/dev/null && bad "add touched policy/state" || pass "adding a rule changes nothing else"

reset
run --add --action deny --port 5353 --proto any >/dev/null; rc=$?
[ "$rc" -eq 0 ] && called "^ufw deny from any to any port 5353 comment LinuxGuardian$" && pass "TCP+UDP rule has no proto word" || bad "any proto: $(cat "$CALLS")"

reset
run --delete 2 --fingerprint "$(fp "$RULE2")" >/dev/null; rc=$?
[ "$rc" -eq 0 ] && called "^ufw --force delete 2$" && pass "delete: the rule you saw is deleted" || bad "delete rc=$rc $(cat "$CALLS" 2>/dev/null)"

reset
out="$(run --delete 2 --fingerprint "$(fp "[ 2] 443/tcp ALLOW IN Anywhere")")"; rc=$?
[ "$rc" -eq 4 ] && ! called "^ufw --force delete" && echo "$out" | grep -q "Nothing was deleted" && pass "delete: a changed list deletes nothing" || bad "stale delete: rc=$rc $out"

reset
run --enable >/dev/null && called "^ufw --force enable$" && pass "enable" || bad "enable"
reset
run --disable >/dev/null && called "^ufw disable$" && grep -lq '"severity":"warning".*turned OFF' "$LG_HOME"/incidents/*.json \
  && pass "disable is recorded as a warning" || bad "disable"
reset
run --default-incoming reject >/dev/null && called "^ufw default reject incoming$" && pass "default incoming reject" || bad "default incoming"
reset
run --logging medium >/dev/null && called "^ufw logging medium$" && pass "logging medium" || bad "logging"
reset
run --restart >/dev/null && called "^systemctl restart ufw$" && pass "restart restarts the service" || bad "restart"
reset; export STUB_RESTART_RC=1
run --restart >/dev/null; rc=$?
[ "$rc" -eq 1 ] && pass "a failed restart is reported as an error" || bad "failed restart rc=$rc"

# ---------------------------------------------------------------- refusals before any prompt
reset; export STUB_PKEXEC=cancel
run --enable >/dev/null; rc=$?
[ "$rc" -eq 2 ] && ! called '^ufw' && pass "dismissed prompt: exit 2, nothing changed" || bad "cancel rc=$rc"

reset; export STUB_ACTIVE=firewalld
out="$(run --enable)"; rc=$?
[ "$rc" -eq 3 ] && ! called pkexec && echo "$out" | grep -q "two firewalls" && pass "firewalld in charge: refuses before any prompt" || bad "firewalld: rc=$rc $out"

# Quotes and semicolons are meant to arrive literally: they are the attack.
# shellcheck disable=SC2089,SC2090
for args in "--default-incoming allow" "--default-outgoing reject" "--logging loud" "--delete 0 --fingerprint x" "--delete 2" \
            "--delete 2;reboot --fingerprint $(fp "$RULE2")" "--add --action open --port 22" "--add --action allow --port 22;reboot" \
            "--add --action allow --port 22 --from \$(reboot)" "--add --action allow --port 22 --label x';reboot;'" \
            "--add --action allow --port 6000:6010 --proto any" "--frobnicate"; do
  reset
  # shellcheck disable=SC2086,SC2090
  out="$(run $args)"; rc=$?
  if [ "$rc" -ne 0 ] && ! called pkexec && ! called '^ufw'; then pass "refused: $args"; else bad "got through: $args (rc=$rc)"; fi
done

# ---------------------------------------------------------------- the root script alone refuses tampered input
script="$(awk "index(\$0, \"PRIV_SCRIPT_FIREWALL=\")==1{f=1; sub(/^PRIV_SCRIPT_FIREWALL='/, \"\")} f{print} f && /^'\$/ {exit}" "$SCRIPT" | sed '$d')"
[ -n "$script" ] && pass "root script extracted" || bad "couldn't extract the root script"
for tampered in "flush" "reset" "enable now" "default allow incoming" "default incoming allow" "logging loud" \
                "add allow tcp 22 any" "add open tcp 22 any x" "add allow sctp 22 any x" "add allow tcp 22;reboot any x" \
                "add allow tcp :22 any x" "add allow tcp 22 -h x" "add allow tcp 22 1.2.3.4;reboot x" "add allow tcp 22 any x;reboot" \
                "delete 2" "delete 02 $(fp "$RULE2")" "delete 2 XYZ" "delete 2;reboot $(fp "$RULE2")"; do
  reset
  # shellcheck disable=SC2086
  PATH="$SB/bin:/usr/bin:/bin" sh -c "$script" sh $tampered >/dev/null 2>&1; rc=$?
  if [ "$rc" -ne 0 ] && ! called '^ufw'; then pass "root script refuses: $tampered"; else bad "root script accepted: $tampered (rc=$rc)"; fi
done

[ "$fail" -eq 0 ] && echo "All firewall control tests passed." || echo "Some firewall control tests FAILED."
exit "$fail"

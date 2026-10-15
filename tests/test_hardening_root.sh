#!/usr/bin/env bash
# linux_hardening.sh: what reaches root, that undo restores what was recorded, and that nothing else can get through.
set -uo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
SCRIPT="${LG_HARDENING:-$ROOT/LinuxGuardianSuite/linux_hardening.sh}"
fail=0
pass() { echo "OK: $1"; }
bad()  { echo "FAIL: $1"; fail=1; }

SB="$(mktemp -d)"; trap 'rm -rf "$SB"' EXIT
mkdir -p "$SB/bin" "$SB/lg" "$SB/sys/net/ipv4/conf/all" "$SB/sys/net/ipv4" "$SB/sys/kernel" "$SB/etc"
export LG_HOME="$SB/lg" CALLS="$SB/calls" LG_PROC_SYS="$SB/sys" LG_UFW_DEFAULT="$SB/etc/ufw-default" LG_UFW_CONF="$SB/etc/ufw.conf"
echo 1 > "$SB/sys/net/ipv4/conf/all/send_redirects"; echo 1 > "$SB/sys/net/ipv4/tcp_syncookies"; echo 1 > "$SB/sys/kernel/dmesg_restrict"
printf 'IPV6=no\nDEFAULT_INPUT_POLICY="DROP"\n' > "$SB/etc/ufw-default"
printf 'ENABLED=yes\nLOGLEVEL=medium\n' > "$SB/etc/ufw.conf"

cat > "$SB/bin/pkexec" <<'STUB'
#!/bin/sh
printf 'pkexec:%s\n' "$*" >> "$CALLS"
[ "${STUB_PKEXEC:-}" = "cancel" ] && exit 126
exec "$@"
STUB
for t in sysctl ufw; do printf '#!/bin/sh\necho "%s $*" >> "$CALLS"\n' "$t" > "$SB/bin/$t"; done
chmod +x "$SB/bin"/*
run() { PATH="$SB/bin:$PATH" bash "$SCRIPT" "$@" 2>&1; }
called() { grep -q -- "$1" "$CALLS" 2>/dev/null; }
reset() { rm -f "$CALLS"; unset STUB_PKEXEC; }

# sysctl fix needs to write /etc/sysctl.d: the stub pkexec runs the real script, so redirect that path into the sandbox
# by running the fixed script under a shim `sh` that rewrites the target. (The script text itself is unchanged.)
cat > "$SB/bin/sh" <<STUB
#!/bin/bash
args=("\$@")
for i in "\${!args[@]}"; do args[\$i]="\${args[\$i]//\/etc\/sysctl.d\//$SB/etc/}"; args[\$i]="\${args[\$i]//\/etc\/default\/ufw/$SB/etc/ufw-default}"; done
exec /bin/sh "\${args[@]}"
STUB
chmod +x "$SB/bin/sh"
sed -i 's#^printf .pkexec:%s\\n. "\$\*" >> "\$CALLS"#printf "pkexec:%s\\n" "$*" >> "$CALLS"#' "$SB/bin/pkexec"
cat > "$SB/bin/pkexec" <<STUB
#!/bin/sh
printf 'pkexec:%s\n' "\$*" >> "\$CALLS"
[ "\${STUB_PKEXEC:-}" = "cancel" ] && exit 126
shift
exec "$SB/bin/sh" "\$@"
STUB
chmod +x "$SB/bin/pkexec"

reset
out="$(run --apply sysctl)"; rc=$?
[ "$rc" -eq 0 ] && pass "sysctl fix applies" || bad "sysctl rc=$rc: $out"
[ -f "$SB/etc/99-linuxguardian-hardening.conf" ] && grep -q '^net.ipv4.conf.all.send_redirects = 0$' "$SB/etc/99-linuxguardian-hardening.conf" && pass "writes the fixed settings file" || bad "settings file: $(cat "$SB/etc/99-linuxguardian-hardening.conf" 2>&1 | head -3)"
grep -qE 'rp_filter|ptrace_scope' "$SB/etc/99-linuxguardian-hardening.conf" && bad "touches VPN/debugger-sensitive settings" || pass "leaves rp_filter and ptrace_scope alone"
called '^sysctl -e -p ' && pass "loads it with sysctl -e -p (ignores keys this kernel lacks)" || bad "sysctl call: $(grep sysctl "$CALLS")"
python3 -c "import json;d=json.load(open('$SB/lg/state/hardening_undo.json'));print(d['sysctl']['sysctl']['net.ipv4.conf.all.send_redirects'])" | grep -q '^1$' && pass "recorded the previous value (1) for undo" || bad "undo record missing"

reset
out="$(run --undo sysctl)"; rc=$?
[ "$rc" -eq 0 ] && called '^sysctl -e -w net.ipv4.conf.all.send_redirects=1$' && pass "undo restores the recorded value" || bad "undo rc=$rc: $(grep sysctl "$CALLS")"
[ ! -f "$SB/etc/99-linuxguardian-hardening.conf" ] && pass "undo removes the settings file" || bad "file left behind"
[ ! -f "$SB/lg/state/hardening_undo.json" ] || ! grep -q sysctl "$SB/lg/state/hardening_undo.json" && pass "undo record cleared" || bad "record left"

reset
run --undo sysctl >/dev/null; rc=$?
[ "$rc" -eq 3 ] && ! called pkexec && pass "undo with nothing recorded refuses before any prompt" || bad "empty undo rc=$rc"

reset
run --apply ufw_ipv6 >/dev/null; rc=$?
[ "$rc" -eq 0 ] && grep -q '^IPV6=yes$' "$SB/etc/ufw-default" && called '^ufw reload$' && pass "ufw IPv6: set to yes and reloaded" || bad "ipv6 rc=$rc: $(cat "$SB/etc/ufw-default")"
reset
run --undo ufw_ipv6 >/dev/null; rc=$?
[ "$rc" -eq 0 ] && grep -q '^IPV6=no$' "$SB/etc/ufw-default" && pass "ufw IPv6 undo puts IPV6=no back" || bad "ipv6 undo rc=$rc"

reset
run --apply ufw_logging >/dev/null
called '^ufw logging low$' && pass "ufw logging set to low" || bad "logging: $(grep ufw "$CALLS")"
reset
run --undo ufw_logging >/dev/null
called '^ufw logging medium$' && pass "logging undo restores the previous level (medium)" || bad "logging undo: $(grep ufw "$CALLS")"

# Loopback IPv6: on loopback it must stay on (a ::1 that hangs held every login at a black screen on 2026-10-15).
mkdir -p "$SB/sys/net/ipv6/conf/lo"; echo 1 > "$SB/sys/net/ipv6/conf/lo/disable_ipv6"
reset
out="$(run --apply ufw_ipv6)"; rc=$?
[ "$rc" -eq 3 ] && ! called pkexec && echo "$out" | grep -q "loopback" && pass "ufw IPv6 refused while loopback IPv6 is off (no prompt)" || bad "ufw_ipv6 with lo off: rc=$rc $out"
reset
run --apply lo_ipv6 >/dev/null; rc=$?
[ "$rc" -eq 0 ] && called '^sysctl -w net.ipv6.conf.lo.disable_ipv6=0$' && grep -q '^net.ipv6.conf.lo.disable_ipv6 = 0$' "$SB/etc/99-zz-linuxguardian-loopback-ipv6.conf" \
  && pass "lo_ipv6: turned on now and in a file that sorts after 99-*.conf" || bad "lo_ipv6 rc=$rc $(cat "$CALLS" 2>/dev/null)"
python3 -c "import json;d=json.load(open('$SB/lg/state/system_changes.json'));assert d[-1]['what']=='Hardening applied: lo_ipv6' and 'undo lo_ipv6' in d[-1]['undo']" \
  && pass "the change and its undo command are in the login-watch ledger" || bad "ledger entry missing"
reset
run --undo lo_ipv6 >/dev/null; rc=$?
[ "$rc" -eq 0 ] && called '^sysctl -w net.ipv6.conf.lo.disable_ipv6=1$' && [ ! -f "$SB/etc/99-zz-linuxguardian-loopback-ipv6.conf" ] && pass "lo_ipv6 undo restores the recorded value" || bad "lo undo rc=$rc"
script="$(awk "index(\$0, \"PRIV_LO_IPV6_UNDO=\")==1{f=1; sub(/^PRIV_LO_IPV6_UNDO='/, \"\")} f{print} f && /^'\$/ {exit}" "$SCRIPT" | sed '$d')"
for tampered in "2" "1;reboot" "" "-w"; do
  reset
  PATH="$SB/bin:$PATH" sh -c "$script" sh "$tampered" >/dev/null 2>&1; rc=$?
  if [ "$rc" -ne 0 ] && ! called '^sysctl'; then pass "root lo undo refuses: '$tampered'"; else bad "root lo undo accepted: '$tampered'"; fi
done
echo 0 > "$SB/sys/net/ipv6/conf/lo/disable_ipv6"
if grep -rnE 'lo\.disable_ipv6 *= *1|lo\.disable_ipv6=1|all\.disable_ipv6 *= *1|disable_ipv6=1' "$ROOT/LinuxGuardianSuite"/*.sh | grep -v '^\S*:[0-9]*:\s*#' >/dev/null; then
  bad "something in the suite can switch IPv6 off (rule: never on loopback)"
else
  pass "no root script in the suite ever switches IPv6 off"
fi

reset; export STUB_PKEXEC=cancel
run --apply sysctl >/dev/null; rc=$?
[ "$rc" -eq 2 ] && ! python3 -c "import json;d=json.load(open('$SB/lg/state/hardening_undo.json'));assert 'sysctl' in d" 2>/dev/null && pass "dismissed prompt: exit 2, nothing recorded as applied" || bad "cancel rc=$rc"

reset
for evil in rm_everything 'sysctl; reboot' '' ../etc vino_off; do
  out="$(run --apply "$evil")"; rc=$?
  if [ "$rc" -eq 3 ] && ! called pkexec; then pass "refused unknown fix '$evil'"; else bad "'$evil' got through rc=$rc"; fi
done

echo "--- root scripts are fixed text"
for name in PRIV_SYSCTL_APPLY PRIV_SYSCTL_UNDO PRIV_UFW_IPV6_APPLY PRIV_UFW_IPV6_UNDO PRIV_UFW_LOGGING_UNDO PRIV_LO_IPV6_APPLY PRIV_LO_IPV6_UNDO; do
  body="$(awk -v n="$name" 'index($0, n"=")==1{f=1} f{print} f && /^'"'"'$/ {exit}' "$SCRIPT")"
  [ -n "$body" ] || { bad "$name not found"; continue; }
  if grep -qE '`|\$\([^(]|eval|sudo|curl|wget|rm -rf|chmod|ufw (enable|disable|reset|default|allow|deny|delete)' <<<"$body"; then bad "$name contains something it should not"; else pass "$name does only its one job"; fi
done

line="$(grep '^PRIV_UFW_LOGGING_APPLY=' "$SCRIPT")"
[ "$line" = "PRIV_UFW_LOGGING_APPLY='exec ufw logging low'" ] && pass "PRIV_UFW_LOGGING_APPLY is exactly 'ufw logging low'" || bad "logging script changed: $line"

# The undo scripts re-validate: tampered words must be refused by the root script itself.
script="$(awk "index(\$0, \"PRIV_SYSCTL_UNDO=\")==1{f=1; sub(/^PRIV_SYSCTL_UNDO='/, \"\")} f{print} f && /^'\$/ {exit}" "$SCRIPT" | sed '$d')"
for tampered in "kernel.core_pattern 1" "net.ipv4.tcp_syncookies 11" "net.ipv4.tcp_syncookies x" "net.ipv4.tcp_syncookies" "fs.protected_hardlinks 1 evil 1"; do
  reset
  # shellcheck disable=SC2086
  PATH="$SB/bin:$PATH" sh -c "$script" sh $tampered >/dev/null 2>&1; rc=$?
  if [ "$rc" -ne 0 ] && ! called '^sysctl'; then pass "root undo refuses: $tampered"; else bad "root undo accepted: $tampered (rc=$rc)"; fi
done

echo; [ "$fail" -eq 0 ] && echo "all hardening-root checks passed" || echo "SOME CHECKS FAILED"; exit "$fail"

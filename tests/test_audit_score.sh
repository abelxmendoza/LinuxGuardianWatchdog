#!/usr/bin/env bash
# The audit's new scanner-trust checks and its Rating line. The audit also looks at the real
# firewall/ports/disk of whatever machine runs it, so these tests only assert on the lines they
# control (definitions, rootkit) and on the arithmetic being consistent with the printed counts.
set -uo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
AUDIT="${LG_AUDIT:-$ROOT/LinuxGuardianSuite/linux_security_audit.sh}"
fail=0
pass() { echo "OK: $1"; }
bad()  { echo "FAIL: $1"; fail=1; }

SB="$(mktemp -d)"; trap 'rm -rf "$SB"' EXIT
mkdir -p "$SB/bin" "$SB/clam" "$SB/home/scans"
printf '#!/bin/sh\nexit 0\n' > "$SB/bin/rkhunter"; chmod +x "$SB/bin/rkhunter"
export LG_HOME="$SB/home" LG_CLAMAV_DIR="$SB/clam" LG_RKHUNTER_DB="$SB/none.dat"

audit() { PATH="$SB/bin:$PATH" bash "$AUDIT" 2>&1; }
setdefs() { touch -d "$1" "$SB/clam/daily.cld"; }          # setdefs "6 days ago"
setlast() { printf '{"rootkit_check": "%s"}' "$1" > "$SB/home/scans/last.json"; }

setdefs "1 hour ago"; setlast ran
out="$(audit)"
echo "$out" | grep -q "\[ OK \] Virus definitions are current" && pass "fresh definitions pass" || bad "fresh defs: $out"
echo "$out" | grep -q "\[ OK \] Rootkit check has run" && pass "a rootkit check that ran passes" || bad "rootkit ran: $out"

setdefs "6 days ago"; setlast needs_root
out="$(audit)"
echo "$out" | grep -q "\[WARN\] Virus definitions are 6 days old" && pass "6-day-old definitions warn, with the age" || bad "stale defs: $out"
echo "$out" | grep -q "\[WARN\] Rootkit check has not run yet" && pass "a skipped rootkit check warns" || bad "rootkit skipped: $out"

setlast cancelled; echo "$(audit)" | grep -q "\[WARN\] Rootkit check has not run" && pass "a cancelled rootkit check warns" || bad "cancelled"
rm -f "$SB/home/scans/last.json"; echo "$(audit)" | grep -q "\[WARN\] Rootkit check has not run" && pass "never scanned warns" || bad "never scanned"

# Rating = round-half-up((pass + warn/2) / total), computed once, here.
out="$(audit)"
plain="$(sed 's/\x1b\[[0-9;]*m//g' <<<"$out")"
read -r P W F T < <(sed -n 's/.*Score: \([0-9]*\) pass, \([0-9]*\) warn, \([0-9]*\) fail (of \([0-9]*\) checks).*/\1 \2 \3 \4/p' <<<"$plain")
rating="$(sed -n 's/^Rating: \([0-9]*\) of 100.*/\1/p' <<<"$plain")"
want="$(python3 -c "import math;p,w,t=$P,$W,$T;print(math.floor((p+w/2)/t*100+0.5))")"
[ "$rating" = "$want" ] && pass "Rating $rating% matches $P pass / $W warn / $F fail of $T (warn = half)" || bad "rating=$rating want=$want ($P/$W/$F/$T)"
[ $((P+W+F)) -eq "$T" ] && pass "counts add up to the total" || bad "counts don't add up"

echo; [ "$fail" -eq 0 ] && echo "all audit checks passed" || echo "SOME CHECKS FAILED"; exit "$fail"

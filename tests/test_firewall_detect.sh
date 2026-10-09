#!/usr/bin/env bash
# lg_detect_firewall must work for a NORMAL user. Regression: it used to ask
# `ufw status`, which refuses to run without root, so an active firewall was
# reported as "none". Uses stub systemctl/ufw and fixture config files.
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
fail=0
pass() { echo "OK: $1"; }
bad()  { echo "FAIL: $1"; fail=1; }

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
mkdir -p "$SANDBOX/bin" "$SANDBOX/lg"
export LG_HOME="$SANDBOX/lg"

# systemctl is-active <unit>: active only for units listed in STUB_ACTIVE.
cat > "$SANDBOX/bin/systemctl" <<'EOF'
#!/bin/sh
[ "$1" = "is-active" ] || exit 1
[ "$2" = "--quiet" ] && unit="$3" || unit="$2"
for u in ${STUB_ACTIVE:-}; do [ "$u" = "$unit" ] && exit 0; done
exit 3
EOF
# A ufw that behaves like the real one for a normal user.
cat > "$SANDBOX/bin/ufw" <<'EOF'
#!/bin/sh
echo "ERROR: You need to be root to run this script" >&2
exit 1
EOF
chmod +x "$SANDBOX/bin"/*

printf 'ENABLED=yes\nLOGLEVEL=low\n' > "$SANDBOX/ufw-on.conf"
printf 'ENABLED=no\nLOGLEVEL=low\n'  > "$SANDBOX/ufw-off.conf"

detect() {  # detect CONF_PATH   (STUB_ACTIVE from the environment)
  PATH="$SANDBOX/bin:$PATH" LG_UFW_CONF="$1" bash -c \
    "source '$ROOT/LinuxGuardianSuite/config.sh'; source '$ROOT/LinuxGuardianSuite/utils.sh'; lg_detect_firewall" 2>/dev/null
}

r="$(STUB_ACTIVE="ufw" detect "$SANDBOX/ufw-on.conf")"
[ "$r" = "ufw" ] && pass "ufw enabled + running -> ufw (even though 'ufw status' refuses to run without root)" || bad "ufw on: got '$r'"

r="$(STUB_ACTIVE="ufw" detect "$SANDBOX/ufw-off.conf")"
[ "$r" = "none" ] && pass "ufw service up but ENABLED=no -> none (nothing is filtering)" || bad "ufw config off: got '$r'"

r="$(STUB_ACTIVE="" detect "$SANDBOX/ufw-on.conf")"
[ "$r" = "none" ] && pass "ufw configured but service not running -> none" || bad "ufw stopped: got '$r'"

r="$(STUB_ACTIVE="ufw" detect "$SANDBOX/does-not-exist.conf")"
[ "$r" = "ufw" ] && pass "unreadable ufw config + running service -> ufw" || bad "ufw unreadable conf: got '$r'"

r="$(STUB_ACTIVE="firewalld" detect "$SANDBOX/ufw-off.conf")"
[ "$r" = "firewalld" ] && pass "firewalld running -> firewalld" || bad "firewalld: got '$r'"

r="$(STUB_ACTIVE="nftables" detect "$SANDBOX/ufw-off.conf")"
[ "$r" = "nftables" ] && pass "nftables service running -> nftables" || bad "nftables: got '$r'"

r="$(STUB_ACTIVE="" detect "$SANDBOX/ufw-off.conf")"
[ "$r" = "none" ] && pass "nothing running -> none" || bad "none: got '$r'"

# ufw wins when more than one is up.
r="$(STUB_ACTIVE="ufw firewalld" detect "$SANDBOX/ufw-on.conf")"
[ "$r" = "ufw" ] && pass "ufw is preferred when several firewalls are up" || bad "precedence: got '$r'"

exit $fail

#!/usr/bin/env bash
# linux_apps.sh end to end against a fake Ubuntu: what reaches root, and what must never.
set -uo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
APPS="${LG_APPS:-$ROOT/LinuxGuardianSuite/linux_apps.sh}"
FAKE="$ROOT/tests/helpers/fake_apt_world.py"
fail=0
pass() { echo "OK: $1"; }
bad()  { echo "FAIL: $1"; fail=1; }

SB="$(mktemp -d)"; trap 'rm -rf "$SB"' EXIT
mkdir -p "$SB/bin" "$SB/apt/sources.list.d" "$SB/lg"
export LG_HOME="$SB/lg" CALLS="$SB/calls" FAKE_WORLD="$SB/world.json" LG_APT_ROOT="$SB/apt" LG_OS_RELEASE_FILE="$SB/os-release"
UBU="http://archive.ubuntu.com/ubuntu"
echo "deb $UBU jammy main" > "$SB/apt/sources.list"

for t in apt-mark apt-cache dpkg-query dpkg; do
  printf '#!/bin/sh\nexec python3 "%s" %s "$@"\n' "$FAKE" "$t" > "$SB/bin/$t"
done
cat > "$SB/bin/snap" <<STUB
#!/bin/sh
if [ "\$1" = "install" ]; then echo "snap \$*" >> "\$CALLS"; exit 0; fi
exec python3 "$FAKE" snap "\$@"
STUB
cat > "$SB/bin/apt-get" <<'STUB'
#!/bin/sh
echo "apt-get $*" >> "$CALLS"
exit 0
STUB
cat > "$SB/bin/pkexec" <<'STUB'
#!/bin/sh
printf 'pkexec:%s\n' "$*" >> "$CALLS"
[ "${STUB_PKEXEC:-}" = "cancel" ] && exit 126
exec "$@"
STUB
chmod +x "$SB/bin"/*

machine() {  # machine VERSION  -> target laptop: nothing installed, htop available
  printf 'ID=ubuntu\nVERSION_ID="%s"\nVERSION_CODENAME=jammy\nUBUNTU_CODENAME=jammy\n' "$1" > "$SB/os-release"
  cat > "$SB/world.json" <<JSON
{"manual": [], "installed": [], "holds": [], "arch": "amd64", "snaps": [],
 "policy": {"htop": {"candidate": "3.0", "url": "$UBU"}, "vlc": {"candidate": "3.1", "url": "$UBU"}}}
JSON
}
manifest() {  # manifest [EXTRA_NAME]  -> an app list; EXTRA_NAME is added as both an apt and a snap entry
  local extra_apt="" extra_snap=""
  if [ -n "${1:-}" ]; then
    extra_apt=", {\"name\": \"$1\", \"origin\": \"ubuntu\", \"host\": \"archive.ubuntu.com\", \"hardware_specific\": false}"
    extra_snap=", {\"name\": \"$1\", \"channel\": \"x\", \"classic\": false}"
  fi
  cat > "$SB/apps.json" <<JSON
{"schema": 1, "created": "x", "source_machine": "old-laptop",
 "distro": {"id": "ubuntu", "version": "22.04", "codename": "jammy", "arch": "amd64"},
 "apt": [{"name": "htop", "origin": "ubuntu", "host": "archive.ubuntu.com", "hardware_specific": false},
         {"name": "vlc", "origin": "ubuntu", "host": "archive.ubuntu.com", "hardware_specific": false},
         {"name": "nvidia-driver-535", "origin": "ubuntu", "host": "archive.ubuntu.com", "hardware_specific": false},
         {"name": "cursor", "origin": "third_party", "host": "downloads.cursor.com", "hardware_specific": false}$extra_apt],
 "snaps": [{"name": "firefox", "channel": "latest/stable", "classic": false},
           {"name": "code", "channel": "latest/stable", "classic": true}$extra_snap],
 "flatpaks": [], "third_party_repos": [], "holds": []}
JSON
}
run() { PATH="$SB/bin:$PATH" bash "$APPS" "$@" 2>&1; }
reset() { rm -f "$CALLS"; unset STUB_PKEXEC; }
called() { grep -q -- "$1" "$CALLS" 2>/dev/null; }

machine 22.04; manifest
out="$(run --plan "$SB/apps.json")"; rc=$?
[ "$rc" -eq 0 ] && echo "$out" | grep -q "2 Ubuntu apps to install" && echo "$out" | grep -q "1 need a third-party" && echo "$out" | grep -q "1 hardware-specific" && pass "plan: counts what installs, needs a repo, and is skipped" || bad "plan: rc=$rc out=$out"
[ ! -e "$CALLS" ] && pass "plan changes nothing" || bad "plan ran something: $(cat "$CALLS")"

reset
out="$(run --install "$SB/apps.json")"; rc=$?
[ "$rc" -eq 0 ] && pass "install succeeds" || bad "install rc=$rc: $out"
called '^apt-get install -y --no-remove -- htop vlc$' && pass "apt installs exactly the available Ubuntu apps, never removing anything" || bad "apt call: $(grep apt-get "$CALLS")"
called '^snap install firefox$' && pass "plain snap installed" || bad "snap: $(grep snap "$CALLS")"
called 'nvidia' && bad "a hardware package reached the installer" || pass "hardware-specific packages never reach the installer"
called 'cursor' && bad "a third-party app was installed without its repo" || pass "third-party apps are not installed without their repo"
called 'snap install --classic' && bad "classic snap installed without being asked" || pass "classic snaps are not installed unless included"
called 'add-apt-repository\|apt-key\|gpg\|sources.list' && bad "touched repositories or keys" || pass "never touches repositories or keys"

reset
run --install "$SB/apps.json" --include-classic >/dev/null
called '^snap install --classic code$' && pass "classic snap installed when explicitly included" || bad "classic: $(grep snap "$CALLS")"

reset
run --install "$SB/apps.json" --apt-only >/dev/null; ! called '^snap ' && called '^apt-get install' && pass "--apt-only installs only apt packages" || bad "apt-only"
reset
run --install "$SB/apps.json" --snaps-only >/dev/null; called '^snap install' && ! called '^apt-get install' && pass "--snaps-only installs only snaps" || bad "snaps-only"

reset; machine 24.04
out="$(run --install "$SB/apps.json")"; rc=$?
[ "$rc" -eq 3 ] && ! called pkexec && echo "$out" | grep -q "24.04" && pass "a different Ubuntu release is refused before any password prompt" || bad "release mismatch: rc=$rc out=$out"

reset; machine 22.04; export STUB_PKEXEC=cancel
run --install "$SB/apps.json" >/dev/null; rc=$?
[ "$rc" -eq 2 ] && ! called '^apt-get install' && ! called '^snap install' && pass "dismissed password prompt: exit 2, nothing installed" || bad "cancel rc=$rc"

reset; machine 22.04; export FAKE_ALL_AVAILABLE=1     # worst case: the planner would happily offer anything
for evil in '-oAPT::Update::Pre-Invoke::=reboot' 'a;reboot' '$(reboot)' 'UPPER'; do
  manifest "$evil"
  run --install "$SB/apps.json" --include-classic >/dev/null
  if grep -qiF -- "$evil" "$CALLS" 2>/dev/null || called 'reboot'; then bad "tampered name reached the installer: $evil"; else pass "tampered package name '$evil' never reaches root"; fi
  reset
done

unset FAKE_ALL_AVAILABLE
echo "--- root scripts are fixed text"
for name in PRIV_SCRIPT_APT_INSTALL PRIV_SCRIPT_SNAP_INSTALL PRIV_SCRIPT_SNAP_CLASSIC; do
  body="$(awk -v n="$name" 'index($0, n"=")==1{f=1} f{print} f && /^'"'"'$/ {exit}' "$APPS")"
  [ -n "$body" ] || { bad "$name not found"; continue; }
  if grep -qE '`|\$\(|sudo|apt-key|add-apt-repository|--allow|curl|wget|rm |sources|gpg|dpkg -i' <<<"$body"; then bad "$name contains something it should not"; else pass "$name does only its one job"; fi
done

echo; [ "$fail" -eq 0 ] && echo "all app-transfer checks passed" || echo "SOME CHECKS FAILED"; exit "$fail"

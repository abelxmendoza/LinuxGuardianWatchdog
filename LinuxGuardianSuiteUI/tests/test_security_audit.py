"""Audit regressions: unavailable evidence must not become a security pass."""
from pathlib import Path
import subprocess

import pytest

SUITE = Path(__file__).resolve().parents[2] / 'LinuxGuardianSuite'


@pytest.mark.parametrize('status,exit_code,expected', [
    ('Status: active', 0, 'ufw'),
    ('Status: inactive', 0, 'none'),
    ('', 1, 'unknown'),
])
def test_firewall_exact_status(status, exit_code, expected):
    script = '''
source "$1/utils.sh"
command() { [[ "$1" == "-v" && "$2" == "ufw" ]]; }
ufw() { printf '%s\\n' "$STATUS"; return "$EXIT_CODE"; }
lg_detect_firewall
'''
    import os
    result = subprocess.run(['bash', '-c', script, 'audit-test', str(SUITE)],
                            env={**os.environ, 'STATUS': status, 'EXIT_CODE': str(exit_code)},
                            capture_output=True, text=True, check=True)
    assert result.stdout.strip() == expected


@pytest.mark.parametrize('periodic,timer,expected', [
    ('APT::Periodic::Unattended-Upgrade "1";\nAPT::Periodic::Update-Package-Lists "1";', 0, 'pass'),
    ('APT::Periodic::Unattended-Upgrade "0";', 0, 'warn'),
    ('APT::Periodic::Unattended-Upgrade "1";\nAPT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Enable "0";', 0, 'warn'),
    ('APT::Periodic::Unattended-Upgrade "1";\nAPT::Periodic::Update-Package-Lists "1";', 1, 'warn'),
])
def test_update_settings_and_timer(periodic, timer, expected):
    import os
    source = (SUITE / 'linux_security_audit.sh').read_text()
    block = source.split('# Automatic updates\n', 1)[1].split('# LUKS', 1)[0]
    setup = '''
command() { [[ "$1" == "-v" && ( "$2" == "apt-config" || "$2" == "unattended-upgrade" ) ]]; }
apt-config() { printf '%s\\n' "$PERIODIC"; }
systemctl() { return "$TIMER"; }
check() { printf 'RESULT:%s\\n' "$2"; }
'''
    result = subprocess.run(['bash', '-c', setup + block],
                            env={**os.environ, 'PERIODIC': periodic, 'TIMER': str(timer)},
                            capture_output=True, text=True, check=True)
    assert f'RESULT:{expected}' in result.stdout

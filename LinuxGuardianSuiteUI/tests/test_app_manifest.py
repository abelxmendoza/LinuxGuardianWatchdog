"""App manifest: export what's here, plan what would happen there, and never trust the file."""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import app_manifest as am  # noqa: E402

FAKE = ROOT / "tests" / "helpers" / "fake_apt_world.py"
UBU = "http://archive.ubuntu.com/ubuntu"


def install_fake_tools(bindir: Path) -> None:
    bindir.mkdir(exist_ok=True)
    for tool in ("apt-mark", "apt-cache", "dpkg-query", "dpkg", "snap"):
        p = bindir / tool
        p.write_text(f'#!/bin/sh\nexec python3 "{FAKE}" {tool} "$@"\n')
        p.chmod(p.stat().st_mode | stat.S_IEXEC)


def make_machine(tmp: Path, monkeypatch, world: dict, *, version="22.04", arch="amd64", sources="") -> None:
    (tmp / "w.json").write_text(json.dumps({**world, "arch": arch}))
    (tmp / "os-release").write_text(f'ID=ubuntu\nVERSION_ID="{version}"\nVERSION_CODENAME=jammy\nUBUNTU_CODENAME=jammy\n')
    apt = tmp / "apt"
    (apt / "sources.list.d").mkdir(parents=True, exist_ok=True)
    (apt / "sources.list").write_text(sources or f"deb {UBU} jammy main\n")
    install_fake_tools(tmp / "bin")
    monkeypatch.setenv("PATH", f"{tmp/'bin'}:{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_WORLD", str(tmp / "w.json"))
    monkeypatch.setenv("LG_OS_RELEASE_FILE", str(tmp / "os-release"))
    monkeypatch.setenv("LG_APT_ROOT", str(apt))


SOURCE_WORLD = {
    "manual": ["htop", "vlc", "ros-humble-desktop", "linux-image-5.15.0-100-generic", "nvidia-driver-535",
               "cursor", "localthing", "curl"],
    "installed": ["htop", "vlc", "ros-humble-desktop", "linux-image-5.15.0-100-generic", "nvidia-driver-535", "cursor", "localthing", "curl"],
    "holds": ["ros-humble-desktop"],
    "policy": {
        "htop": {"installed": "3.0", "candidate": "3.0", "url": UBU}, "vlc": {"installed": "3.1", "candidate": "3.1", "url": UBU},
        "curl": {"installed": "7", "candidate": "7", "url": UBU},
        "ros-humble-desktop": {"installed": "0.10", "candidate": "0.10", "url": "http://packages.ros.org/ros2/ubuntu"},
        "cursor": {"installed": "3.1", "candidate": "3.1", "url": "https://downloads.cursor.com/aptrepo"},
        "linux-image-5.15.0-100-generic": {"installed": "5.15", "candidate": "5.15", "url": UBU},
        "nvidia-driver-535": {"installed": "535", "candidate": "535", "url": UBU},
        "localthing": {"installed": "1", "candidate": "1", "url": None},
    },
    "snaps": [["firefox", "latest/stable", "mozilla**", "-"], ["code", "latest/stable", "vscode**", "classic"],
              ["core22", "latest/stable", "canonical**", "base"], ["snapd", "latest/stable", "canonical**", "snapd"],
              ["gnome-42-2204", "latest/stable", "canonical**", "-"]],
}


@pytest.fixture()
def source(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    make_machine(src, monkeypatch, SOURCE_WORLD, sources=(
        f"deb {UBU} jammy main\ndeb https://user:s3cret@downloads.cursor.com/aptrepo stable main\n"
        "deb http://packages.ros.org/ros2/ubuntu jammy main\n"))
    return src


def test_export_contents_and_classification(source):
    m = am.build_manifest()
    assert m["schema"] == 1 and m["distro"]["version"] == "22.04"
    rows = {r["name"]: r for r in m["apt"]}
    assert rows["htop"]["origin"] == "ubuntu" and not rows["htop"]["hardware_specific"]
    assert rows["ros-humble-desktop"]["origin"] == "third_party" and rows["ros-humble-desktop"]["host"] == "packages.ros.org"
    assert rows["localthing"]["origin"] == "local"
    assert rows["linux-image-5.15.0-100-generic"]["hardware_specific"] and rows["nvidia-driver-535"]["hardware_specific"]
    assert m["holds"] == ["ros-humble-desktop"]


def test_snaps_skip_infrastructure_and_remember_classic(source):
    names = {s["name"]: s for s in am.build_manifest()["snaps"]}
    assert set(names) == {"firefox", "code"}               # core22, snapd, gnome-* runtimes are not "apps"
    assert names["code"]["classic"] and not names["firefox"]["classic"]


def test_credentials_in_repo_urls_never_reach_the_manifest(source):
    text = json.dumps(am.build_manifest())
    assert "s3cret" not in text and "user:" not in text
    assert any(r["host"] == "downloads.cursor.com" for r in json.loads(text)["third_party_repos"])


def test_redact():
    assert am.redact("https://u:p@host.example/x") == "https://host.example/x"
    assert am.redact("http://archive.ubuntu.com/ubuntu") == "http://archive.ubuntu.com/ubuntu"


def test_the_manifest_has_no_home_files_or_secrets(source):
    m = am.build_manifest()
    assert set(m) == {"schema", "created", "source_machine", "distro", "apt", "snaps", "flatpaks", "third_party_repos", "holds"}


# ------------------------------------------------------------------ the target machine
@pytest.fixture()
def manifest(source):
    return am.build_manifest()


def target(tmp_path, monkeypatch, world, **kw):
    t = tmp_path / "tgt"
    t.mkdir(exist_ok=True)
    make_machine(t, monkeypatch, world, **kw)


def test_plan_sorts_everything_honestly(tmp_path, monkeypatch, manifest):
    target(tmp_path, monkeypatch, {
        "installed": ["curl"],
        "policy": {"htop": {"candidate": "3.0", "url": UBU}, "vlc": {"candidate": None}},   # vlc not in this machine's sources
    })
    plan = am.make_plan(manifest)
    a = plan["apt"]
    assert plan["compatible"]
    assert a["have"] == ["curl"]
    assert a["install"] == ["htop"]
    assert [u["name"] for u in a["unavailable"]] == sorted(u["name"] for u in a["unavailable"])
    assert {"vlc", "localthing"} <= {u["name"] for u in a["unavailable"]}
    assert {n["name"] for n in a["needs_repo"]} == {"ros-humble-desktop", "cursor"}      # third-party, and this laptop lacks their repos
    assert set(a["hardware"]) == {"linux-image-5.15.0-100-generic", "nvidia-driver-535"}
    assert plan["snaps"]["install"] == ["firefox"] and plan["snaps"]["install_classic"] == ["code"]


def test_a_third_party_app_whose_repo_is_already_configured_is_installable(tmp_path, monkeypatch, manifest):
    target(tmp_path, monkeypatch, {"installed": [], "policy": {"ros-humble-desktop": {"candidate": "0.10", "url": "http://packages.ros.org/ros2/ubuntu"}}},
           sources=f"deb {UBU} jammy main\ndeb http://packages.ros.org/ros2/ubuntu jammy main\n")
    assert "ros-humble-desktop" in am.make_plan(manifest)["apt"]["install"]


def test_everything_already_here_means_nothing_to_do(tmp_path, monkeypatch, manifest):
    target(tmp_path, monkeypatch, {"installed": SOURCE_WORLD["installed"], "snaps": SOURCE_WORLD["snaps"]})
    plan = am.make_plan(manifest)
    assert plan["apt"]["install"] == [] and plan["snaps"]["install"] == [] and plan["snaps"]["install_classic"] == []


@pytest.mark.parametrize("kw,fragment", [({"version": "24.04"}, "24.04"), ({"arch": "arm64"}, "arm64")])
def test_a_different_release_or_cpu_installs_nothing(tmp_path, monkeypatch, manifest, kw, fragment):
    target(tmp_path, monkeypatch, {"installed": [], "policy": {"htop": {"candidate": "3.0", "url": UBU}}}, **kw)
    plan = am.make_plan(manifest)
    assert not plan["compatible"] and fragment in plan["reason"]
    assert plan["apt"]["install"] == [] and plan["snaps"]["install"] == [] and plan["snaps"]["install_classic"] == []
    assert am.installable_names(manifest, "apt") == [] and am.installable_names(manifest, "snap-classic") == []


@pytest.mark.parametrize("evil", ["-oAPT::Update::Pre-Invoke::=rm -rf ~", "../../etc/passwd", "a;b", "$(reboot)", "UPPER", "", "a b", "`id`"])
def test_a_tampered_manifest_cannot_smuggle_names_to_the_installer(tmp_path, monkeypatch, manifest, evil):
    target(tmp_path, monkeypatch, {"installed": [], "policy": {"htop": {"candidate": "3.0", "url": UBU}}})
    manifest["apt"].append({"name": evil, "origin": "ubuntu", "host": "archive.ubuntu.com", "hardware_specific": False})
    manifest["snaps"].append({"name": evil, "classic": False})
    names = am.installable_names(manifest, "apt") + am.installable_names(manifest, "snap")
    assert evil not in names or evil == ""
    assert all(am.ui.PACKAGE_NAME_RE.match(n) or am.SNAP_NAME_RE.match(n) for n in names)
    plan = am.make_plan(manifest)
    assert plan["apt"]["invalid"] and plan["snaps"]["invalid"]


def test_a_manifest_that_claims_a_package_is_not_hardware_cannot_override_the_rule(tmp_path, monkeypatch, manifest):
    target(tmp_path, monkeypatch, {"installed": [], "policy": {"nvidia-driver-535": {"candidate": "535", "url": UBU}}})
    for r in manifest["apt"]:
        r["hardware_specific"] = False                      # the file lies
    assert "nvidia-driver-535" not in am.make_plan(manifest)["apt"]["install"]


@pytest.mark.parametrize("bad", [None, [], {"schema": 2}, {"schema": 1}, {"schema": 1, "distro": {}, "apt": "x", "snaps": []}])
def test_validate_rejects_nonsense(bad):
    assert am.validate_manifest(bad)


def test_export_file_is_private(tmp_path, source, monkeypatch):
    out = tmp_path / "apps.json"
    monkeypatch.setattr(sys, "argv", ["app_manifest.py", "--export", str(out)])
    assert am.main() == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600 and json.loads(out.read_text())["schema"] == 1

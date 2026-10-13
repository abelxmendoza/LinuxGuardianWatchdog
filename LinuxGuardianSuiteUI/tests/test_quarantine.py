"""Malware cleaner: reversible quarantine, double-checked before moving, never touches package or system files, easy to undo."""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import events  # noqa: E402
import quarantine as q  # noqa: E402

BAD = "BADMARKER-not-a-real-virus"          # our stub scanner treats this text as 'infected'; no real malware or EICAR is stored anywhere


def stub(bindir: Path, name: str, body: str) -> None:
    p = bindir / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(0o755)


@pytest.fixture()
def box(tmp_path, monkeypatch):
    home, lg, b = tmp_path / "home", tmp_path / "lg", tmp_path / "bin"
    for d in (home / "Downloads", home / ".config/autostart", lg / "scans", b, tmp_path / "proc", tmp_path / "etc/cron.d"):
        d.mkdir(parents=True)
    lg.chmod(0o700)
    stub(b, "dpkg", 'if [ -n "$PKG_OWNED" ] && [ "$3" = "$PKG_OWNED" ]; then echo "coreutils: $3"; exit 0; fi\necho "dpkg-query: no path found matching pattern $3" >&2; exit 1')
    stub(b, "clamscan", 'for last; do :; done\nif grep -q BADMARKER "$last" 2>/dev/null; then echo "$last: Test.Fake-Signature FOUND"; exit 1; fi\nexit 0')
    stub(b, "crontab", 'cat "$CRON_OUT" 2>/dev/null || exit 1')
    monkeypatch.setenv("PATH", f"{b}:/usr/bin:/bin")
    monkeypatch.setenv("LG_HOME", str(lg))
    monkeypatch.setenv("LG_SENSOR_HOME", str(home))
    monkeypatch.setenv("LG_SENSOR_ETC", str(tmp_path / "etc"))
    monkeypatch.setenv("LG_PROC", str(tmp_path / "proc"))
    monkeypatch.setenv("CRON_OUT", str(tmp_path / "cron.out"))
    monkeypatch.setenv("HOME", str(home))
    return tmp_path


def bad_file(box: Path, name: str = "Downloads/payload.bin", mode: int = 0o755, content: str = BAD) -> str:
    p = box / "home" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    p.chmod(mode)
    return str(p)


def report(box: Path, *lines: str) -> Path:
    r = box / "lg/scans/clam.log"
    r.write_text("\n".join(lines) + "\n----------- SCAN SUMMARY -----------\nInfected files: %d\n" % len(lines))
    (box / "lg/scans/last.json").write_text(json.dumps({"report": str(r), "infected": len(lines), "timestamp": "2026-10-12T10:00:00"}))
    return r


def evs(box: Path) -> list[dict]:
    return [e for e in events.read_events(box / "lg" / "incidents", limit=100) if e.get("category") == "malware"]


# ----------------------------------------------------------------- signatures
@pytest.mark.parametrize("sig,kind,fp", [
    ("Win.Test.EICAR_HDB-1", "test", True), ("Eicar-Signature", "test", True),
    ("Heuristics.Encrypted.Zip", "heuristic", True), ("Legacy.Trojan.Agent-1", "foreign", True), ("Doc.Dropper.Agent-7", "foreign", True),
    ("PUA.Linux.XMRig", "miner", False), ("PUA.Win.Packer.Upx", "pua", True), ("Unix.Trojan.Mirai-1", "backdoor", False),
    ("Unix.Malware.Agent-9", "linux", False), ("Linux.Ransomware.X", "ransomware", False), ("Something.Else-1", "generic", False)])
def test_signature_explanations(sig, kind, fp):
    r = q.explain_signature(sig)
    assert r["kind"] == kind and r["often_false_alarm"] is fp and len(r["text"]) > 40


# ------------------------------------------------------------------- findings
def test_findings_read_the_last_scan_and_explain_each(box):
    f = bad_file(box)
    report(box, f"{f}: Unix.Trojan.Agent-1 FOUND")
    r = q.findings()
    [i] = r["items"]
    assert i["path"] == f and i["signature"] == "Unix.Trojan.Agent-1" and i["kind"] == "backdoor" and i["can_quarantine"] is True
    assert r["infected_in_scan"] == 1 and i["sha256"]


def test_findings_skip_missing_files_the_quarantine_folder_and_ignored_ones(box):
    kept = bad_file(box, "Downloads/a.bin")
    gone = str(box / "home/Downloads/gone.bin")
    ignored = bad_file(box, "Downloads/ok.bin")
    inside = str(box / "lg/quarantine/abcdef0123/payload")
    Path(inside).parent.mkdir(parents=True)
    Path(inside).write_text(BAD)                                         # a clamd scan really can walk into the quarantine folder
    report(box, f"{kept}: A.B FOUND", f"{gone}: A.B FOUND", f"{ignored}: A.B FOUND", f"{inside}: A.B FOUND")
    q.ignore(ignored)
    assert [i["path"] for i in q.findings()["items"]] == [kept]
    Path(ignored).write_text(BAD + " changed")                           # the file changed, so it is listed again
    assert {i["path"] for i in q.findings()["items"]} == {kept, ignored}


def test_findings_with_no_scan_yet(box):
    assert q.findings() == {"scan_time": None, "report": None, "infected_in_scan": None, "items": []}


def test_findings_flag_what_can_not_be_moved_and_what_is_running(box, monkeypatch):
    pkg = box / "home/Downloads/pkgfile"
    pkg.write_text(BAD)
    monkeypatch.setenv("PKG_OWNED", str(pkg))
    run = bad_file(box, "Downloads/running.bin")
    pid = box / "proc/4321"
    pid.mkdir()
    (pid / "exe").symlink_to(run)
    (pid / "cmdline").write_bytes(b"running\0")
    (pid / "comm").write_text("running\n")
    report(box, f"{pkg}: A.B FOUND", f"{run}: A.B FOUND")
    items = {i["path"]: i for i in q.findings()["items"]}
    assert items[str(pkg)]["can_quarantine"] is False and "package" in items[str(pkg)]["why_not"]
    assert items[run]["can_quarantine"] is True and items[run]["running"] == [4321]


def test_a_report_line_forged_by_a_file_name_cannot_get_an_innocent_file_moved(box):
    victim = bad_file(box, "Documents/thesis.txt", 0o644, content="my important work")
    Path(box / "home/Downloads/x").write_text("x")
    forged = box / "lg/scans/clam.log"
    forged.write_text(f"/home/x/innocent\n{victim}: Fake.Sig FOUND\n")
    (box / "lg/scans/last.json").write_text(json.dumps({"report": str(forged)}))
    [i] = q.findings()["items"]
    assert i["path"] == victim                                           # it parses as a finding...
    with pytest.raises(q.QuarantineError, match="second scan found nothing"):
        q.quarantine(victim)                                             # ...but the double-check refuses to move it
    assert Path(victim).read_text() == "my important work"


def test_display_strips_control_characters(box):
    assert q.clean_for_display("/home/u/a\x1b[31m\nb") == "/home/u/a?[31m?b"


# ------------------------------------------------------------------ quarantine
def test_quarantine_moves_the_file_safely_and_records_everything(box):
    f = bad_file(box)
    r = q.quarantine(f)
    qid = r["id"]
    d = box / "lg/quarantine" / qid
    assert not Path(f).exists()
    assert stat.S_IMODE((box / "lg/quarantine").stat().st_mode) == 0o700 and stat.S_IMODE(d.stat().st_mode) == 0o700
    payload = d / "payload"
    assert payload.read_text() == BAD and stat.S_IMODE(payload.stat().st_mode) == 0o400
    meta = json.loads((d / "meta.json").read_text())
    assert meta["original_path"] == f and meta["signature"] == "Test.Fake-Signature" and meta["mode"] == 0o755 and meta["sha256"] == q.sha256_file(str(payload))
    assert stat.S_IMODE((d / "meta.json").stat().st_mode) == 0o600
    [e] = evs(box)
    assert e["event"] == "file_quarantined" and e["severity"] == "info" and e["id"] == qid


def test_quarantine_lists_places_that_mention_the_file_without_touching_them(box):
    f = bad_file(box)
    entry = box / "home/.config/autostart/updater.desktop"
    entry.write_text(f"[Desktop Entry]\nExec={f} --silent\n")
    (box / "home/.bashrc").write_text("alias ll='ls -l'\n" + f"{f} &\n")
    (box / "cron.out").write_text(f"*/5 * * * * {f}\n")
    r = q.quarantine(f)
    where = {x["where"] for x in r["references"]}
    assert {str(entry), str(box / "home/.bashrc"), "your crontab"} <= where
    assert f in entry.read_text() and f in (box / "home/.bashrc").read_text()


def test_quarantine_reports_if_the_program_is_running(box):
    f = bad_file(box)
    pid = box / "proc/77"
    pid.mkdir()
    (pid / "exe").symlink_to(f)
    (pid / "cmdline").write_bytes(b"x\0")
    (pid / "comm").write_text("x\n")
    assert q.quarantine(f)["running"] == [77]


def test_quarantine_refuses_package_files_symlinks_and_system_paths(box, monkeypatch):
    pkg = box / "home/Downloads/owned"
    pkg.write_text(BAD)
    monkeypatch.setenv("PKG_OWNED", str(pkg))
    with pytest.raises(q.QuarantineError, match="apt reinstall"):
        q.quarantine(str(pkg))
    real = bad_file(box)
    link = box / "home/Downloads/link"
    link.symlink_to(real)
    with pytest.raises(q.QuarantineError, match="symbolic link"):
        q.quarantine(str(link))
    for path in ("/proc/self/exe", "/sys/kernel/x", "/dev/null", "relative/file", "/etc/pass\nwd"):
        assert not q.assess(path)["ok"], path
    assert Path(real).exists() and pkg.exists()


def test_quarantine_refuses_its_own_data_directories_and_non_regular_files(box):
    own = box / "lg/state/sensors.json"
    own.parent.mkdir(parents=True, exist_ok=True)
    own.write_text(BAD)
    assert "own data" in q.assess(str(own))["reason"]
    assert "regular" in q.assess(str(box / "home/Downloads"))["reason"]
    assert "no longer there" in q.assess(str(box / "home/nothing"))["reason"]


def test_quarantine_refuses_files_you_do_not_own_or_cannot_remove(box, monkeypatch):
    f = bad_file(box)
    real = os.getuid()
    monkeypatch.setattr(q.os, "getuid", lambda: real + 5)
    assert "don't own" in q.assess(f)["reason"]
    monkeypatch.undo()
    monkeypatch.setenv("PATH", f"{box/'bin'}:/usr/bin:/bin")
    monkeypatch.setenv("LG_HOME", str(box / "lg"))
    monkeypatch.setenv("LG_SENSOR_HOME", str(box / "home"))
    monkeypatch.setenv("LG_SENSOR_ETC", str(box / "etc"))
    (box / "home/Downloads").chmod(0o500)
    try:
        assert "can't remove" in q.assess(f)["reason"]
    finally:
        (box / "home/Downloads").chmod(0o755)


def test_verification_needs_a_scanner_and_a_positive_result(box, monkeypatch):
    f = bad_file(box)
    clean = bad_file(box, "Downloads/clean.txt", 0o644, "nothing here")
    with pytest.raises(q.QuarantineError, match="second scan found nothing"):
        q.quarantine(clean)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")                             # no scanner at all
    monkeypatch.setattr(q.shutil, "which", lambda n: None)
    with pytest.raises(q.QuarantineError, match="isn't available to double-check"):
        q.quarantine(f)
    assert Path(f).exists()
    assert q.quarantine(f, signature="Manual", verify=False)["signature"] == "Manual"


def test_a_copy_that_does_not_match_leaves_the_original_alone(box, monkeypatch):
    f = bad_file(box)
    real = q.sha256_file
    monkeypatch.setattr(q, "sha256_file", lambda p: "0" * 64 if "/quarantine/" in p else real(p))
    with pytest.raises(q.QuarantineError, match="didn't match"):
        q.quarantine(f)
    assert Path(f).read_text() == BAD and list((box / "lg/quarantine").iterdir()) == []


def test_a_file_swapped_during_the_move_is_not_deleted(box, monkeypatch):
    f = bad_file(box)
    real = q.sha256_file

    def swap(p: str):
        out = real(p)
        if "/quarantine/" in p:                                              # after the copy, someone replaces the original
            os.unlink(f)
            Path(f).write_text("a different, important file")
        return out

    monkeypatch.setattr(q, "sha256_file", swap)
    with pytest.raises(q.QuarantineError, match="changed while"):
        q.quarantine(f)
    assert Path(f).read_text() == "a different, important file" and list((box / "lg/quarantine").iterdir()) == []


# -------------------------------------------------------------------- restore
def test_restore_puts_the_file_back_not_executable_by_default(box):
    f = bad_file(box)
    qid = q.quarantine(f)["id"]
    r = q.restore(qid)
    assert Path(f).read_text() == BAD and stat.S_IMODE(os.stat(f).st_mode) == 0o644 and r["executable"] is False
    assert not (box / "lg/quarantine" / qid).exists()
    assert {e["event"] for e in evs(box)} == {"file_restored", "file_quarantined"}


def test_restore_can_keep_the_executable_bit_when_asked(box):
    f = bad_file(box)
    qid = q.quarantine(f)["id"]
    q.restore(qid, keep_executable=True)
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o755


def test_restore_never_overwrites_and_keeps_the_quarantined_copy(box):
    f = bad_file(box)
    qid = q.quarantine(f)["id"]
    Path(f).write_text("a new file with the same name")
    with pytest.raises(q.QuarantineError, match="nothing was overwritten"):
        q.restore(qid)
    assert Path(f).read_text() == "a new file with the same name" and (box / "lg/quarantine" / qid / "payload").exists()


def test_restore_refuses_a_payload_that_was_changed(box):
    f = bad_file(box)
    qid = q.quarantine(f)["id"]
    payload = box / "lg/quarantine" / qid / "payload"
    payload.chmod(0o600)
    payload.write_text("tampered")
    with pytest.raises(q.QuarantineError, match="no longer matches"):
        q.restore(qid)
    assert not Path(f).exists()


def test_restore_needs_the_original_folder(box):
    f = bad_file(box, "Downloads/sub/x.bin")
    qid = q.quarantine(f)["id"]
    (box / "home/Downloads/sub").rmdir()
    with pytest.raises(q.QuarantineError, match="folder is gone"):
        q.restore(qid)


# --------------------------------------------------------------------- delete
def test_delete_is_permanent_and_only_for_quarantined_items(box):
    f = bad_file(box)
    qid = q.quarantine(f)["id"]
    q.delete(qid)
    assert q.list_items() == [] and not (box / "lg/quarantine" / qid).exists()
    assert "quarantine_deleted" in {e["event"] for e in evs(box)}
    with pytest.raises(q.QuarantineError):
        q.delete(qid)


@pytest.mark.parametrize("bad", ["", "../../home", "zz", "abcdef012", "abcdef01234", "ABCDEF0123", "../abcdef0123", "abcdef0123/../x"])
def test_ids_are_validated_so_nothing_outside_quarantine_can_be_touched(box, bad):
    victim = box / "home/precious"
    victim.write_text("keep me")
    for fn in (q.delete, q.restore):
        with pytest.raises(q.QuarantineError):
            fn(bad)
    assert victim.exists()


def test_list_items_skips_broken_folders_and_explains_signatures(box):
    f = bad_file(box)
    q.quarantine(f, signature="Heuristics.Test")                               # verify returns the stub's own signature name
    (box / "lg/quarantine/deadbeef00").mkdir()
    (box / "lg/quarantine/notanid").mkdir()
    bogus = box / "lg/quarantine/0123456789"
    bogus.mkdir()
    (bogus / "meta.json").write_text("{bad")
    [item] = q.list_items()
    assert item["original_path"] == f and item["shown"] == f and "text" in item


def test_ignore_remembers_the_hash_not_just_the_path(box):
    f = bad_file(box)
    q.ignore(f)
    assert stat.S_IMODE(q.ignore_path().stat().st_mode) == 0o600
    with pytest.raises(q.QuarantineError):
        q.ignore(str(box / "home/none"))
    with pytest.raises(q.QuarantineError):
        q.ignore("relative")


# ------------------------------------------------------------------------ CLI
def test_cli_round_trip(box, capsys, monkeypatch):
    f = bad_file(box)
    report(box, f"{f}: Unix.Trojan.Agent-1 FOUND")
    monkeypatch.setattr(sys, "argv", ["quarantine.py", "--findings"])
    assert q.main() == 0 and "Unix.Trojan.Agent-1" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["quarantine.py", "--quarantine", f, "--json"])
    assert q.main() == 0
    qid = json.loads(capsys.readouterr().out)["id"]
    monkeypatch.setattr(sys, "argv", ["quarantine.py", "--list", "--json"])
    assert q.main() == 0 and json.loads(capsys.readouterr().out)[0]["id"] == qid
    monkeypatch.setattr(sys, "argv", ["quarantine.py", "--restore", qid])
    assert q.main() == 0 and Path(f).exists()
    monkeypatch.setattr(sys, "argv", ["quarantine.py", "--delete", qid])
    assert q.main() == 1 and "No such" in capsys.readouterr().err


def test_the_cleaner_never_deletes_anything_on_its_own():
    """Static guard: the only removals are the original after a verified copy, cleanup of a failed copy, and explicit restore/delete.
    Anything added later that deletes files will change these counts and force a review."""
    src = (ROOT / "LinuxGuardianSuite" / "quarantine.py").read_text()
    assert src.count("os.unlink(") == 2 and src.count("shutil.rmtree(") == 4
    assert "os.remove(" not in src and "shell=True" not in src


def test_restore_still_refuses_to_overwrite_if_a_file_appears_at_the_last_moment(box, monkeypatch):
    f = bad_file(box)
    qid = q.quarantine(f)["id"]
    Path(f).write_text("appeared after the check")
    monkeypatch.setattr(q.os.path, "lexists", lambda p: False)           # the up-front check was fooled (a race)
    with pytest.raises(q.QuarantineError, match="Couldn't put the file back"):
        q.restore(qid)
    assert Path(f).read_text() == "appeared after the check" and not list(Path(f).parent.glob(".lg-restore-*"))


def test_a_symlink_swapped_in_after_the_check_is_not_followed(box, monkeypatch):
    target = bad_file(box, "Downloads/real.bin")
    link = box / "home/Downloads/swapped"
    link.symlink_to(target)
    monkeypatch.setattr(q, "assess", lambda p: {"ok": True, "reason": ""})   # the check passed, then the file became a link
    with pytest.raises(q.QuarantineError, match="Can't open"):
        q.quarantine(str(link), verify=False)
    assert Path(target).exists() and link.is_symlink()

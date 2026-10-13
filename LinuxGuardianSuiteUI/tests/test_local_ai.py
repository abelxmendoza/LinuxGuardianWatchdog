"""Free local AI setup: honest hardware advice, safe model names, resumable downloads, and a clear next step."""
from __future__ import annotations

import http.server
import json
import stat
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import ai_eval  # noqa: E402
import ai_investigator as ai  # noqa: E402
import local_ai as la  # noqa: E402


class FakeOllama:
    def __init__(self) -> None:
        self.models: list[str] = []
        self.pull_script: list[dict] = []
        self.pulled: list[str] = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path == "/api/tags":
                    body = json.dumps({"models": [{"name": m} for m in outer.models]}).encode()
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(n))
                if self.path == "/api/pull":
                    outer.pulled.append(req["model"])
                    if any(m.get("status") == "success" for m in outer.pull_script):
                        outer.models.append(req["model"])               # registered before the reply, so the client never races it
                    self.send_response(200)
                    self.end_headers()
                    for msg in outer.pull_script:
                        self.wfile.write((json.dumps(msg) + "\n").encode())

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture()
def box(tmp_path, monkeypatch):
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")        # no real ollama or nvidia-smi leaks in
    monkeypatch.setenv("LG_MEMINFO", str(tmp_path / "meminfo"))
    monkeypatch.setenv("LG_LOCAL_AI_DISK", str(tmp_path))
    (tmp_path / "meminfo").write_text("MemTotal:       65011712 kB\nMemFree: 1 kB\n")
    smi = tmp_path / "smi"
    smi.write_text("#!/bin/sh\necho 'NVIDIA GeForce RTX 5070 Laptop GPU, 8151'\n")
    smi.chmod(smi.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("LG_NVIDIA_SMI", str(smi))
    srv = FakeOllama()
    cfg = dict(ai.DEFAULT_CONFIG, ollama_url=srv.url)
    ai.save_config(cfg)
    monkeypatch.setattr(la.shutil, "disk_usage", lambda p: type("U", (), {"free": 200 * la.GIB})())
    yield tmp_path, srv
    srv.close()


def add_ollama_binary(tmp_path):
    p = tmp_path / "bin" / "ollama"
    p.write_text("#!/bin/sh\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


# ---------------------------------------------------------------- hardware
def test_hardware_reads_gpu_ram_and_disk(box):
    hw = la.hardware()
    assert hw["gpu"] == {"name": "NVIDIA GeForce RTX 5070 Laptop GPU", "vram_gb": 8.0}
    assert hw["ram_gb"] == 62.0 and hw["disk_free_gb"] == 200.0


def test_hardware_without_a_gpu_or_meminfo_still_answers(box, monkeypatch):
    monkeypatch.setenv("LG_NVIDIA_SMI", "/nonexistent/nvidia-smi")
    monkeypatch.setenv("LG_MEMINFO", "/nonexistent")
    hw = la.hardware()
    assert hw["gpu"] is None and hw["ram_gb"] is None


def test_a_broken_nvidia_smi_is_ignored(box, monkeypatch):
    bad = box[0] / "badsmi"
    bad.write_text("#!/bin/sh\necho 'Failed to initialize NVML'\nexit 9\n")
    bad.chmod(0o755)
    monkeypatch.setenv("LG_NVIDIA_SMI", str(bad))
    assert la.hardware()["gpu"] is None


# --------------------------------------------------------------------- fit
HW8 = {"gpu": {"name": "x", "vram_gb": 8.0}, "ram_gb": 62.0, "disk_free_gb": 200.0}


def test_fit_on_an_8gb_card_matches_reality():
    assert la.fit(1.9, HW8)["level"] == "fits"
    assert la.fit(4.7, HW8)["level"] == "tight"                     # 4.7 + 2.6 overhead leaves under 1 GB of headroom
    assert la.fit(5.2, HW8)["level"] == "tight"
    assert la.fit(9.0, HW8)["level"] == "slow"                      # CPU with plenty of RAM
    assert la.fit(40.0, HW8)["level"] == "too_big"


def test_fit_without_a_gpu_is_slow_not_impossible_when_ram_allows():
    hw = {"gpu": None, "ram_gb": 32.0, "disk_free_gb": 100.0}
    assert la.fit(4.7, hw)["level"] == "slow" and la.fit(9.0, hw)["level"] == "slow"
    assert la.fit(4.7, {"gpu": None, "ram_gb": 8.0, "disk_free_gb": 100.0})["level"] == "too_big"


def test_fit_refuses_when_the_disk_is_nearly_full():
    r = la.fit(4.7, {**HW8, "disk_free_gb": 5.0})
    assert r["level"] == "too_big" and "disk" in r["text"]


def test_model_name_validation():
    for ok in ("qwen2.5:7b", "llama3.1:8b", "qwen3:8b", "library/mistral:latest", "gemma2"):
        assert la.valid_model_name(ok), ok
    for bad in ("", "a b", "x;rm -rf /", "../../etc", "$(id)", "a\nb", "-rf", "http://evil/x", "qwen2.5:7b --insecure", "A" * 200):
        assert not la.valid_model_name(bad), bad


# ------------------------------------------------------------------- status
def test_status_steps_walk_the_person_from_nothing_to_done(box, monkeypatch):
    tmp, srv = box
    srv.close()                                                      # nothing listening at all
    assert la.status()["step"] == "install"
    add_ollama_binary(tmp)
    assert la.status()["step"] == "start"


def test_status_pull_choose_grade_done(box):
    tmp, srv = box
    add_ollama_binary(tmp)
    assert la.status()["step"] == "pull"
    srv.models.append("qwen2.5:7b")
    s = la.status()
    assert s["step"] == "choose" and s["installed_models"][0]["tag"] == "qwen2.5:7b" and s["installed_models"][0]["grade"]["state"] == "ungraded"
    ok, _ = la.use("qwen2.5:7b")
    assert ok and la.status()["step"] == "grade"
    ai_eval.save({"model": "qwen2.5:7b", "hash": ai_eval.scenario_hash(), "grade": "Good", "score": 1, "critical": 1, "results": [], "reasons": [], "time": 1})
    s = la.status()
    assert s["step"] == "done" and s["chosen"] == "qwen2.5:7b" and s["installed_models"][0]["chosen"] is True


def test_status_marks_a_stale_grade_as_needing_a_rerun(box):
    tmp, srv = box
    add_ollama_binary(tmp)
    srv.models.append("qwen2.5:7b")
    la.use("qwen2.5:7b")
    ai_eval.save({"model": "qwen2.5:7b", "hash": "old", "grade": "Good", "score": 1, "critical": 1, "results": [], "reasons": [], "time": 1})
    assert la.status()["step"] == "grade"


def test_suggestions_are_fitted_to_this_machine(box):
    s = la.status()
    by = {r["tag"]: r for r in s["suggestions"]}
    assert by["qwen2.5:3b"]["fit"]["level"] == "fits" and by["qwen2.5:7b"]["fit"]["level"] == "tight" and by["qwen2.5:14b"]["fit"]["level"] == "slow"
    assert s["recommended"] == "qwen2.5:7b"
    assert s["install_command"].startswith("curl -fsSL https://ollama.com/") and s["install_page"].startswith("https://ollama.com/")


def test_nothing_in_the_status_ever_runs_an_installer(box, monkeypatch):
    called = []
    monkeypatch.setattr(la.subprocess, "run", lambda *a, **k: called.append(a) or type("R", (), {"stdout": ""})())
    la.status()
    assert all("install.sh" not in json.dumps(c) for c in called)


# ------------------------------------------------------------------- pulling
def test_pull_streams_progress_and_succeeds(box):
    _, srv = box
    srv.pull_script = [{"status": "pulling manifest"}, {"status": "pulling abc", "total": 1000, "completed": 100},
                       {"status": "pulling abc", "total": 1000, "completed": 100}, {"status": "pulling abc", "total": 1000, "completed": 900},
                       {"status": "verifying sha256 digest"}, {"status": "success"}]
    out: list[str] = []
    assert la.pull("qwen2.5:7b", out.append) == 0
    assert [l for l in out if l.startswith("PROGRESS")] == ["PROGRESS 10 Downloading qwen2.5:7b", "PROGRESS 90 Downloading qwen2.5:7b"]     # no repeats
    assert out[-1] == "Downloaded qwen2.5:7b." and "qwen2.5:7b" in srv.models


def test_pull_reports_server_errors(box):
    _, srv = box
    srv.pull_script = [{"error": "pull model manifest: file does not exist"}]
    out: list[str] = []
    assert la.pull("nosuchmodel:1b", out.append) == 1 and out[-1].startswith("[error] pull model manifest")


def test_pull_with_ollama_down_explains(box):
    _, srv = box
    srv.close()
    out: list[str] = []
    assert la.pull("qwen2.5:7b", out.append) == 1 and "Is it running" in out[-1]


def test_pull_that_ends_early_says_so(box):
    _, srv = box
    srv.pull_script = [{"status": "pulling abc", "total": 1000, "completed": 400}]
    out: list[str] = []
    assert la.pull("qwen2.5:7b", out.append) == 1 and "ended early" in out[-1]


def test_pull_rejects_bad_names_before_touching_the_network(box):
    _, srv = box
    out: list[str] = []
    assert la.pull("x; rm -rf ~", out.append) == 2
    assert srv.pulled == []


# ----------------------------------------------------------------------- use
def test_use_requires_a_downloaded_model_and_saves_the_choice(box):
    _, srv = box
    ok, msg = la.use("qwen2.5:7b")
    assert not ok and "isn't downloaded" in msg
    srv.models.append("qwen2.5:7b")
    ok, msg = la.use("qwen2.5:7b")
    assert ok and "Nothing leaves the machine" in msg
    cfg = ai.load_config()
    assert cfg["backend"] == "ollama" and cfg["ollama_model"] == "qwen2.5:7b" and cfg["ollama_url"] == srv.url


def test_use_when_ollama_is_down_or_name_is_bad(box):
    _, srv = box
    ok, msg = la.use("a b")
    assert not ok and "model name" in msg
    srv.close()
    ok, msg = la.use("qwen2.5:7b")
    assert not ok and "isn't running" in msg
    assert ai.load_config()["backend"] == "off"


def test_cli_status_use_and_pull(box, monkeypatch, capsys):
    _, srv = box
    srv.pull_script = [{"status": "success"}]
    monkeypatch.setattr(sys, "argv", ["local_ai.py", "--status", "--json"])
    assert la.main() == 0 and json.loads(capsys.readouterr().out)["step"] in ("install", "pull", "start")
    monkeypatch.setattr(sys, "argv", ["local_ai.py", "--pull", "qwen2.5:7b"])
    assert la.main() == 0
    monkeypatch.setattr(sys, "argv", ["local_ai.py", "--use", "qwen2.5:7b"])
    assert la.main() == 0
    monkeypatch.setattr(sys, "argv", ["local_ai.py", "--use", "nope:1b"])
    assert la.main() == 1

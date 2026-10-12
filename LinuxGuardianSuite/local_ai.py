#!/usr/bin/env python3
"""Free, private AI on this laptop: what fits, how to set it up, and a way to check it is any good.

The AI investigator can use a model running on your own machine through Ollama (free, open source, nothing leaves the
laptop). This helps you get there without guesswork:

  * what your hardware can run (graphics-card memory, RAM, disk)
  * a short list of models that suit it, with an honest "fits / tight / slow / too big"
  * the official install command to copy (LinuxGuardian never runs an installer for you)
  * downloading a chosen model (several GB, only when you press the button)
  * choosing it for the investigator, then grading it with the quality check (ai_eval.py)

  local_ai.py --status [--json]     hardware, Ollama state, model suggestions and grades
  local_ai.py --pull TAG            download a model through the running Ollama (prints PROGRESS lines)
  local_ai.py --use TAG             make the investigator use this local model

Test hooks: LG_HOME, LG_AI_OLLAMA_URL, LG_NVIDIA_SMI, LG_MEMINFO, LG_LOCAL_AI_DISK.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

import ai_eval  # noqa: E402
import ai_investigator as ai  # noqa: E402

GIB = 1024 ** 3
INSTALL_COMMAND = "curl -fsSL https://ollama.com/install.sh | sh"
INSTALL_PAGE = "https://ollama.com/download/linux"
MODEL_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,60}(?:/[a-z0-9][a-z0-9._-]{0,60})?(?::[A-Za-z0-9][A-Za-z0-9._-]{0,40})?")

# Sizes are approximate download sizes for the default (4-bit) builds; they are shown as "about".
CANDIDATES = [
    {"tag": "qwen2.5:7b", "title": "Qwen 2.5 (7B)", "gb": 4.7, "note": "Follows instructions and JSON formats well for its size."},
    {"tag": "llama3.1:8b", "title": "Llama 3.1 (8B)", "gb": 4.9, "note": "A widely used all-rounder."},
    {"tag": "qwen3:8b", "title": "Qwen 3 (8B)", "gb": 5.2, "note": "Newer; reasons step by step, a little slower."},
    {"tag": "qwen2.5:3b", "title": "Qwen 2.5 (3B)", "gb": 1.9, "note": "For small machines. Expect weaker judgement: run the quality check."},
    {"tag": "qwen2.5:14b", "title": "Qwen 2.5 (14B)", "gb": 9.0, "note": "More capable, needs a big graphics card or lots of RAM and patience."},
]
CONTEXT_OVERHEAD_GB = 2.6          # room for the conversation window (16k tokens) and runtime buffers


def _read(path: str) -> str:
    try:
        return Path(path).read_text()
    except OSError:
        return ""


def hardware() -> dict:
    """GPU memory, RAM and free disk. Everything is optional: a laptop without an NVIDIA card still works, just slower."""
    gpu = None
    exe = os.environ.get("LG_NVIDIA_SMI") or shutil.which("nvidia-smi")
    if exe:
        try:
            out = subprocess.run([exe, "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=8,
                                 check=False).stdout.strip().splitlines()
            if out:
                name, _, mib = out[0].rpartition(",")
                if mib.strip().isdigit():
                    gpu = {"name": name.strip(), "vram_gb": round(int(mib.strip()) / 1024, 1)}
        except (OSError, subprocess.TimeoutExpired):
            pass
    m = re.search(r"MemTotal:\s+(\d+) kB", _read(os.environ.get("LG_MEMINFO", "/proc/meminfo")))
    ram = round(int(m.group(1)) / 1024 / 1024, 1) if m else None
    try:
        free = round(shutil.disk_usage(os.environ.get("LG_LOCAL_AI_DISK", str(Path.home()))).free / GIB, 1)
    except OSError:
        free = None
    return {"gpu": gpu, "ram_gb": ram, "disk_free_gb": free}


def fit(gb: float, hw: dict) -> dict:
    """How a model of this download size will run here: fits | tight | slow | too_big."""
    need = gb + CONTEXT_OVERHEAD_GB
    vram = (hw.get("gpu") or {}).get("vram_gb")
    ram = hw.get("ram_gb")
    disk = hw.get("disk_free_gb")
    if disk is not None and disk < gb + 2:
        return {"level": "too_big", "text": f"Not enough free disk space (needs about {gb:.1f} GB)."}
    if vram is not None and vram >= need + 1:
        return {"level": "fits", "text": "Fits in your graphics card: fast."}
    if vram is not None and vram >= need:
        return {"level": "tight", "text": "Fits, but tightly: close GPU-heavy programs (simulators, games) first."}
    if ram is not None and ram >= need * 2:
        return {"level": "slow", "text": "Too big for the graphics card; runs on the CPU, which is much slower."}
    return {"level": "too_big", "text": "Too big for this machine."}


def valid_model_name(tag: str) -> bool:
    return bool(MODEL_NAME.fullmatch(tag or ""))


def ollama_state(url: str) -> dict:
    models = ai.ollama_models(url)
    return {"installed": shutil.which("ollama") is not None, "reachable": models is not None, "models": models or []}


def status() -> dict:
    cfg = ai.load_config()
    url = cfg.get("ollama_url") or ai.OLLAMA_URL
    hw = hardware()
    ol = ollama_state(url)
    rec = []
    for c in CANDIDATES:
        f = fit(c["gb"], hw)
        rec.append({**c, "fit": f, "installed": c["tag"] in ol["models"], "grade": ai_eval.grade_for(c["tag"]) if c["tag"] in ol["models"] else None})
    first_ok = next((r["tag"] for r in rec if r["fit"]["level"] in ("fits", "tight")), None)
    installed = [{"tag": m, "grade": ai_eval.grade_for(m), "chosen": cfg["backend"] == "ollama" and cfg["ollama_model"] == m} for m in ol["models"]]
    if not ol["installed"] and not ol["reachable"]:
        step = "install"
    elif not ol["reachable"]:
        step = "start"
    elif not ol["models"]:
        step = "pull"
    elif not (cfg["backend"] == "ollama" and cfg["ollama_model"] in ol["models"]):
        step = "choose"
    elif ai_eval.grade_for(cfg["ollama_model"])["state"] != "graded":
        step = "grade"
    else:
        step = "done"
    return {"hardware": hw, "ollama": ol, "suggestions": rec, "recommended": first_ok, "installed_models": installed, "step": step,
            "chosen": cfg["ollama_model"] if cfg["backend"] == "ollama" else "", "install_command": INSTALL_COMMAND, "install_page": INSTALL_PAGE,
            "start_command": "ollama serve"}


# ================================================================== actions
def pull(tag: str, emit=print) -> int:
    """Download a model through the local Ollama server. Streams PROGRESS lines. Returns an exit code."""
    if not valid_model_name(tag):
        emit("[error] That doesn't look like a model name (for example qwen2.5:7b).")
        return 2
    cfg = ai.load_config()
    url = (cfg.get("ollama_url") or ai.OLLAMA_URL).rstrip("/")
    req = urllib.request.Request(url + "/api/pull", data=json.dumps({"model": tag, "stream": True}).encode(),
                                 headers={"Content-Type": "application/json"})
    last = -1
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - the user's own local Ollama
            for raw in resp:
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if msg.get("error"):
                    emit(f"[error] {str(msg['error'])[:200]}")
                    return 1
                total, done = msg.get("total"), msg.get("completed")
                if total and done is not None:
                    pct = int(done * 100 / total)
                    if pct != last:
                        last = pct
                        emit(f"PROGRESS {pct} Downloading {tag}")
                elif msg.get("status"):
                    emit(f"STATUS {str(msg['status'])[:80]}")
                if msg.get("status") == "success":
                    emit(f"Downloaded {tag}.")
                    return 0
    except (urllib.error.URLError, OSError, TimeoutError):
        emit(f"[error] Can't reach Ollama at {url}. Is it running? (ollama serve)")
        return 1
    emit("[error] The download ended early. Run it again; Ollama resumes where it stopped.")
    return 1


def use(tag: str) -> tuple[bool, str]:
    cfg = ai.load_config()
    url = cfg.get("ollama_url") or ai.OLLAMA_URL
    models = ai.ollama_models(url)
    if not valid_model_name(tag):
        return False, "That doesn't look like a model name."
    if models is None:
        return False, "Ollama isn't running, so I can't confirm the model is there."
    if tag not in models:
        return False, f"'{tag}' isn't downloaded yet."
    cfg.update(backend="ollama", ollama_model=tag)
    ai.save_config(cfg)
    return True, f"The investigator will now use {tag} on this laptop. Nothing leaves the machine."


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--status", action="store_true")
    g.add_argument("--pull", metavar="TAG")
    g.add_argument("--use", metavar="TAG")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.status:
        s = status()
        if a.json:
            print(json.dumps(s))
        else:
            hw = s["hardware"]
            print(f"GPU: {(hw['gpu'] or {}).get('name', 'none found')} · RAM {hw['ram_gb']} GB · free disk {hw['disk_free_gb']} GB")
            print(f"Ollama: {'running' if s['ollama']['reachable'] else 'installed, not running' if s['ollama']['installed'] else 'not installed'}")
            for r in s["suggestions"]:
                print(f"  {r['tag']:<14} ~{r['gb']} GB  {r['fit']['text']}")
        return 0
    if a.pull:
        return pull(a.pull)
    ok, msg = use(a.use)
    print(msg, file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

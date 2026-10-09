#!/usr/bin/env python3
"""A fake Ubuntu for testing: stands in for apt-mark, apt-cache, dpkg-query, dpkg and snap.

Reads the machine described in $FAKE_WORLD (JSON):
  {"manual": [...], "installed": [...], "holds": [...], "arch": "amd64",
   "policy": {"pkg": {"installed": "1.0", "candidate": "1.0", "url": "http://archive.ubuntu.com/ubuntu"}},
   "snaps": [["name", "channel", "publisher", "notes"], ...]}
Usage: fake_apt_world.py TOOL ARGS...  (TOOL is the command being impersonated)
"""
import json
import os
import sys

world = json.load(open(os.environ["FAKE_WORLD"]))
tool, args = sys.argv[1], sys.argv[2:]

if tool == "apt-mark":
    if args[:1] == ["showmanual"]:
        print("\n".join(world.get("manual", [])))
    elif args[:1] == ["showhold"]:
        print("\n".join(world.get("holds", [])))
elif tool == "dpkg-query":
    for name in world.get("installed", []):
        print(f"{name}\tii ")
elif tool == "dpkg":
    if args[:1] == ["--print-architecture"]:
        print(world.get("arch", "amd64"))
elif tool == "apt-cache":
    for name in args[1:]:
        info = world.get("policy", {}).get(name)
        if info is None and os.environ.get("FAKE_ALL_AVAILABLE"):
            info = {"candidate": "1.0", "url": "http://archive.ubuntu.com/ubuntu"}   # worst case: every name looks installable
        print(f"{name}:")
        if info is None:
            print("  Installed: (none)\n  Candidate: (none)\n  Version table:")
            continue
        inst, cand, url = info.get("installed"), info.get("candidate"), info.get("url")
        print(f"  Installed: {inst or '(none)'}\n  Candidate: {cand or '(none)'}\n  Version table:")
        if inst:
            print(f" *** {inst} 500")
            print(f"        500 {url or '/var/lib/dpkg/status'} jammy/main amd64 Packages" if url else "        100 /var/lib/dpkg/status")
            if url:
                print("        100 /var/lib/dpkg/status")
        elif cand:
            print(f"     {cand} 500\n        500 {url} jammy/main amd64 Packages")
elif tool == "snap":
    if args[:1] == ["list"]:
        print("Name  Version  Rev  Tracking  Publisher  Notes")
        for n, ch, pub, notes in world.get("snaps", []):
            print(f"{n}  1.0  1  {ch}  {pub}  {notes}")

#!/usr/bin/env python3
"""Stand-in for the `gsettings` CLI: values live in the JSON file named by $FAKE_GSETTINGS ("schema key" -> text)."""
import json
import os
import sys

store_path = os.environ["FAKE_GSETTINGS"]
store = json.load(open(store_path))
cmd, args = sys.argv[1], sys.argv[2:]
key = " ".join(args[:2])
if cmd == "get":
    if key not in store:
        print(f"No such key “{args[1]}”", file=sys.stderr)
        sys.exit(1)
    print(store[key])
elif cmd == "set":
    if key not in store:
        sys.exit(1)
    if os.environ.get("FAKE_GSETTINGS_FAIL") == key:
        sys.exit(1)
    store[key] = args[2]
    json.dump(store, open(store_path, "w"))

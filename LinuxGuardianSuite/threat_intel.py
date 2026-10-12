#!/usr/bin/env python3
"""Known-bad internet addresses: is this laptop talking to one?  (free public lists, no account, no cost)

Two free, no-login lists of internet addresses that security researchers have flagged:

  firehol_level1  attack sources and hijacked networks, merged by the FireHOL project from several feeds
  feodo           servers that run botnet "command and control" (abuse.ch Feodo Tracker, CC0)

The lists are downloaded ONLY when you ask (or, once you have turned this on, at most once a day from the live
monitor). Matching happens entirely on this laptop: no address of yours is ever sent anywhere.

Safety rules for the download itself: https only, fixed host allow-list, size cap, every line validated, private
and reserved ranges thrown away (a poisoned list can't make your own network look bad), and a list that looks
broken keeps the old copy instead of replacing it.

  threat_intel.py --status [--json]    what is loaded and how old it is
  threat_intel.py --update [--force]   download/refresh the lists now (turns the feature on)
  threat_intel.py --check IP           is this address on a list?
  threat_intel.py --off                turn it off and forget the downloaded lists

Test hooks: LG_HOME, LG_THREAT_FEEDS (JSON {name: url}), LG_THREAT_ALLOW_LOCAL=1 (permit http://127.0.0.1 for tests), LG_THREAT_NOW.
"""
from __future__ import annotations

import argparse
import bisect
import ipaddress
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SUITE_DIR = Path(__file__).resolve().parent
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

from events import lg_home  # noqa: E402

DAY = 86400
REFRESH_AFTER = DAY                  # the live monitor refreshes at most this often
STALE_AFTER = 14 * DAY               # older than this and the status says so
MAX_BYTES = 8 * 1024 * 1024
TIMEOUT = 20
MIN_PREFIX = 8                       # a /7 or wider in a blocklist is a mistake or an attack, not a threat list
ALLOWED_HOSTS = {"raw.githubusercontent.com", "feodotracker.abuse.ch"}

FEEDS = {
    "firehol_level1": {
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "title": "FireHOL level 1",
        "what": "attack sources and hijacked networks",
        "min_entries": 500,          # the real list has thousands; far fewer means a broken download
    },
    "feodo": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "title": "abuse.ch Feodo Tracker",
        "what": "botnet command-and-control servers",
        "min_entries": 0,            # legitimately empty some weeks
    },
}


def now() -> float:
    return float(os.environ.get("LG_THREAT_NOW") or time.time())


def base_dir() -> Path:
    return lg_home() / "threat_intel"


def config_path() -> Path:
    return base_dir() / "config.json"


def feed_defs() -> dict:
    """The built-in feeds, or the test override."""
    raw = os.environ.get("LG_THREAT_FEEDS")
    if not raw:
        return FEEDS
    try:
        urls = json.loads(raw)
        return {n: {**FEEDS.get(n, {"title": n, "what": "test feed"}), "url": u, "min_entries": 0} for n, u in urls.items()}
    except (json.JSONDecodeError, AttributeError):
        return FEEDS


# ============================================================ parsing
def parse_feed(text: str) -> tuple[list[tuple[int, int]], int, int]:
    """Text -> (ranges, usable_lines, bad_lines). Private/reserved/oversized ranges are dropped, not counted bad."""
    ranges: list[tuple[int, int]] = []
    bad = 0
    usable = 0
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        token = line.split()[0]
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            bad += 1
            continue
        if net.version != 4:
            continue                              # the sensor only watches IPv4 today
        usable += 1
        if net.prefixlen < MIN_PREFIX or not net.is_global or net.is_multicast:
            continue                              # private, loopback, link-local, CGNAT, multicast, bogon, or absurdly wide
        ranges.append((int(net.network_address), int(net.broadcast_address)))
    return ranges, usable, bad


def merge(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if out and start <= out[-1][1] + 1:
            if end > out[-1][1]:
                out[-1] = (out[-1][0], end)
        else:
            out.append((start, end))
    return out


# ============================================================ storage
def _read_json(path: Path) -> dict:
    try:
        d = json.loads(path.read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data))
    tmp.replace(path)


def enabled() -> bool:
    return bool(_read_json(config_path()).get("enabled"))


def feed_path(name: str) -> Path:
    return base_dir() / f"{name}.json"


def load_feed(name: str) -> dict:
    return _read_json(feed_path(name))


# ============================================================ fetching
def _url_ok(url: str) -> bool:
    p = urllib.parse.urlparse(url)
    if os.environ.get("LG_THREAT_ALLOW_LOCAL") == "1" and p.scheme == "http" and p.hostname in ("127.0.0.1", "localhost"):
        return True
    return p.scheme == "https" and p.hostname in ALLOWED_HOSTS


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect could send us to a host that isn't on the allow-list, so follow none."""

    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


def fetch(url: str, etag: str = "") -> tuple[str, str | None, str]:
    """-> (status, text, etag). status: ok | unchanged | error:<why>."""
    if not _url_ok(url):
        return "error:address not allowed", None, ""
    req = urllib.request.Request(url, headers={"User-Agent": "LinuxGuardianWatchdog/threat-intel", "Accept": "text/plain"})
    if etag:
        req.add_header("If-None-Match", etag)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            data = resp.read(MAX_BYTES + 1)
            new_etag = resp.headers.get("ETag", "") or ""
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return "unchanged", None, etag
        return f"error:server answered {exc.code}", None, ""
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return f"error:{getattr(exc, 'reason', exc)}", None, ""
    if len(data) > MAX_BYTES:
        return "error:the list is unexpectedly large", None, ""
    try:
        return "ok", data.decode("utf-8"), new_etag
    except UnicodeDecodeError:
        return "error:the list is not text", None, ""


def update_feed(name: str, spec: dict, force: bool = False) -> dict:
    """Refresh one list. Never replaces a good copy with a bad one."""
    old = load_feed(name)
    status, text, etag = fetch(spec["url"], "" if force else old.get("etag", ""))
    t = now()
    if status == "unchanged":
        old["checked"] = t
        _write_json(feed_path(name), old)
        return {"name": name, "result": "unchanged", "entries": len(old.get("ranges", []))}
    if status != "ok" or text is None:
        return {"name": name, "result": "failed", "why": status.removeprefix("error:"), "entries": len(old.get("ranges", []))}
    ranges, usable, bad = parse_feed(text)
    if bad > max(3, (usable + bad) * 0.05):
        return {"name": name, "result": "failed", "why": "the list is malformed, kept the old copy", "entries": len(old.get("ranges", []))}
    merged = merge(ranges)
    if usable < spec.get("min_entries", 0):
        return {"name": name, "result": "failed", "why": f"only {usable} entries (expected {spec['min_entries']}+), kept the old copy",
                "entries": len(old.get("ranges", []))}
    _write_json(feed_path(name), {"fetched": t, "checked": t, "etag": etag, "ranges": merged, "source_entries": usable})
    return {"name": name, "result": "updated", "entries": len(merged)}


def update(force: bool = False) -> dict:
    """Download every list (turns the feature on: the person asked for this)."""
    _write_json(config_path(), {"enabled": True})
    results = [update_feed(n, s, force) for n, s in feed_defs().items()]
    ok = [r for r in results if r["result"] in ("updated", "unchanged")]
    return {"ok": bool(ok), "feeds": results}


def refresh_if_due() -> dict | None:
    """What the live monitor calls: refresh once a day, only if the person turned this on. Never raises."""
    if not enabled():
        return None
    try:
        t = now()
        due = any(t - load_feed(n).get("checked", 0) >= REFRESH_AFTER for n in feed_defs())
        return update() if due else None
    except Exception:  # noqa: BLE001 - a failed refresh must never stop the sensors
        return None


def turn_off() -> None:
    shutil.rmtree(base_dir(), ignore_errors=True)


# ============================================================ matching
class Intel:
    """All downloaded lists, ready to answer 'is this address on one?'"""

    def __init__(self) -> None:
        self.feeds: dict[str, tuple[list[int], list[int]]] = {}
        for name in feed_defs():
            data = load_feed(name)
            ranges = [r for r in data.get("ranges", []) if isinstance(r, list) and len(r) == 2 and all(isinstance(x, int) for x in r)]
            ranges.sort()
            self.feeds[name] = ([r[0] for r in ranges], [r[1] for r in ranges])

    def __bool__(self) -> bool:
        return any(starts for starts, _ in self.feeds.values())

    def match(self, ip: str) -> list[str]:
        try:
            a = ipaddress.ip_address(ip.strip("[]"))
        except ValueError:
            return []
        if a.version != 4 or not a.is_global or a.is_multicast:
            return []
        n = int(a)
        hits = []
        for name, (starts, ends) in self.feeds.items():
            i = bisect.bisect_right(starts, n) - 1
            if i >= 0 and n <= ends[i]:
                hits.append(name)
        return hits


def load() -> Intel | None:
    """An Intel if the person turned this on and a list exists, else None (the sensor then does nothing)."""
    if not enabled():
        return None
    intel = Intel()
    return intel if intel else None


def describe_hit(names: list[str]) -> str:
    defs = feed_defs()
    return " and ".join(f"{defs[n]['title']} ({defs[n]['what']})" for n in names if n in defs)


# ============================================================ status
def status() -> dict:
    t = now()
    feeds = []
    for name, spec in feed_defs().items():
        d = load_feed(name)
        fetched = d.get("fetched")
        feeds.append({"name": name, "title": spec["title"], "what": spec["what"], "entries": len(d.get("ranges", [])),
                      "fetched": fetched, "age_sec": None if fetched is None else int(max(0, t - fetched))})
    is_on = enabled()
    have = [f for f in feeds if f["fetched"] is not None]
    oldest = max((f["age_sec"] for f in have), default=None)
    if not is_on:
        level, text = "off", "Off: no known-bad address lists downloaded."
    elif not have:
        level, text = "warning", "On, but no lists have been downloaded yet."
    elif oldest is not None and oldest > STALE_AFTER:
        level, text = "warning", f"Lists are {oldest // DAY} days old; they usually update daily."
    else:
        total = sum(f["entries"] for f in feeds)
        level, text = "ok", f"Checking connections against {total:,} known-bad address ranges."
    return {"enabled": is_on, "level": level, "text": text, "feeds": feeds}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--status", action="store_true")
    g.add_argument("--update", action="store_true")
    g.add_argument("--check", metavar="IP")
    g.add_argument("--off", action="store_true")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.status:
        s = status()
        print(json.dumps(s) if a.json else s["text"])
        return 0
    if a.update:
        r = update(a.force)
        if a.json:
            print(json.dumps(r))
        else:
            for f in r["feeds"]:
                why = f" ({f['why']})" if f.get("why") else ""
                print(f"{f['name']}: {f['result']}{why}, {f['entries']:,} ranges")
        return 0 if r["ok"] else 1
    if a.off:
        turn_off()
        print("Known-bad address checking is off and the downloaded lists were removed.")
        return 0
    intel = load()
    if intel is None:
        print("Not turned on: run --update first.", file=sys.stderr)
        return 1
    hits = intel.match(a.check)
    print(json.dumps(hits) if a.json else (f"{a.check} is on: {describe_hit(hits)}" if hits else f"{a.check} is not on any downloaded list."))
    return 0


if __name__ == "__main__":
    sys.exit(main())

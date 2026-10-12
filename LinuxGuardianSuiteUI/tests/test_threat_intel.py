"""Known-bad address matching: safe downloading, strict parsing, correct lookups, and the sensor/incident wiring."""
from __future__ import annotations

import http.server
import json
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "LinuxGuardianSuite"))

import incidents  # noqa: E402
import sensors as sn  # noqa: E402
import threat_intel as ti  # noqa: E402
from test_sensors import DAY, add_proc, at, box, sensor_events, ss_line  # noqa: E402,F401  (box is a fixture)

# Real public addresses on purpose: Python treats documentation ranges (198.51.100.0/24 ...) as private.
BAD_NET = "45.9.148.0/24"
BAD_IP = "45.9.148.77"
FEODO_IP = "162.243.103.246"
GOOD_IP = "93.184.216.34"
FIREHOL = "# firehol_level1\n" + BAD_NET + "\n10.0.0.0/8\n192.168.0.0/16\n0.0.0.0/8\n100.64.0.0/10\n224.0.0.0/4\n" \
          + "\n".join(f"203.0.{i}.0/24" for i in range(1, 11)) + "\n"
FEODO = "# Feodo\n" + FEODO_IP + "\n"


class Feed:
    """A tiny local web server standing in for the real list hosts."""

    def __init__(self) -> None:
        self.bodies: dict[str, bytes] = {}
        self.etags: dict[str, str] = {}
        self.status: dict[str, int] = {}
        self.hits: list[tuple[str, str | None]] = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                outer.hits.append((self.path, self.headers.get("If-None-Match")))
                code = outer.status.get(self.path, 200)
                et = outer.etags.get(self.path, "")
                if code == 200 and et and self.headers.get("If-None-Match") == et:
                    code = 304
                self.send_response(code)
                if et:
                    self.send_header("ETag", et)
                self.end_headers()
                if code == 200:
                    self.wfile.write(outer.bodies.get(self.path, b""))

            def log_message(self, *a):  # silence
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def url(self, name: str) -> str:
        return f"{self.base}/{name}"

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()                       # actually refuse connections, rather than let them queue until the timeout


@pytest.fixture()
def feeds(tmp_path, monkeypatch):
    f = Feed()
    f.bodies["/firehol"] = FIREHOL.encode()
    f.bodies["/feodo"] = FEODO.encode()
    monkeypatch.setenv("LG_HOME", str(tmp_path / "lg"))
    monkeypatch.setenv("LG_THREAT_ALLOW_LOCAL", "1")
    monkeypatch.setenv("LG_THREAT_FEEDS", json.dumps({"firehol_level1": f.url("firehol"), "feodo": f.url("feodo")}))
    yield f
    f.close()


# ------------------------------------------------------------------ parsing
def test_parse_keeps_public_ranges_and_drops_private_reserved_and_absurd():
    text = "\n".join(["# c", "; c", "", "45.9.148.0/24", "1.2.3.4", "10.1.2.3", "127.0.0.1", "169.254.1.1", "100.64.1.1", "224.1.1.1", "0.0.0.0/0",
                      "8.0.0.0/7", "2001:db8::/32", "9.9.9.9 ; SBL123", "8.8.8.0/24 # trailing"])
    ranges, usable, bad = ti.parse_feed(text)
    got = {(ti.ipaddress.ip_address(a).compressed, ti.ipaddress.ip_address(b).compressed) for a, b in ranges}
    assert got == {("45.9.148.0", "45.9.148.255"), ("1.2.3.4", "1.2.3.4"), ("9.9.9.9", "9.9.9.9"), ("8.8.8.0", "8.8.8.255")}
    assert bad == 0 and usable > len(ranges)          # dropped ranges are counted as usable lines, not as damage


def test_parse_counts_garbage_lines_as_bad():
    _, _, bad = ti.parse_feed("1.2.3.4\n<html>\nnot an ip\n5.6.7.8\n")
    assert bad == 2


def test_merge_joins_overlapping_and_adjacent_ranges():
    assert ti.merge([(10, 20), (15, 30), (31, 40), (50, 60)]) == [(10, 40), (50, 60)]
    assert ti.merge([(5, 100), (10, 20)]) == [(5, 100)]


# ----------------------------------------------------------------- updating
def test_update_downloads_validates_and_turns_the_feature_on(feeds):
    assert ti.status()["enabled"] is False and ti.load() is None
    r = ti.update()
    assert r["ok"] and {f["name"]: f["result"] for f in r["feeds"]} == {"firehol_level1": "updated", "feodo": "updated"}
    intel = ti.load()
    assert intel.match(BAD_IP) == ["firehol_level1"]
    assert intel.match("45.9.149.1") == [] and intel.match(GOOD_IP) == []
    assert intel.match(FEODO_IP) == ["feodo"]
    assert intel.match("10.0.0.5") == [] and intel.match("not an address") == [] and intel.match("2001:db8::1") == []
    assert ti.status()["level"] == "ok"


def test_matching_is_exact_at_range_edges(feeds):
    ti.update()
    intel = ti.load()
    assert intel.match("45.9.148.0") and intel.match("45.9.148.255")
    assert not intel.match("45.9.147.255") and not intel.match("45.9.149.0")


def test_private_ranges_in_a_list_never_match_local_addresses(feeds):
    ti.update()
    intel = ti.load()
    assert all(intel.match(ip) == [] for ip in ("10.2.3.4", "192.168.1.1", "127.0.0.1", "100.64.9.9", "0.1.2.3"))


def test_a_broken_download_keeps_the_good_copy(feeds):
    ti.update()
    before = ti.load_feed("firehol_level1")["ranges"]
    feeds.bodies["/firehol"] = b"<html>captive portal</html>\n" * 20
    r = ti.update(force=True)
    res = {f["name"]: f for f in r["feeds"]}["firehol_level1"]
    assert res["result"] == "failed" and "malformed" in res["why"]
    assert ti.load_feed("firehol_level1")["ranges"] == before
    assert ti.load().match(BAD_IP)


def test_a_suspiciously_small_list_is_rejected_when_a_minimum_is_known(feeds, monkeypatch):
    spec = {"url": feeds.url("firehol"), "title": "t", "what": "w", "min_entries": 500}
    r = ti.update_feed("firehol_level1", spec)
    assert r["result"] == "failed" and "only" in r["why"]
    assert ti.load_feed("firehol_level1") == {}


def test_http_errors_and_unreachable_servers_fail_softly(feeds):
    feeds.status["/feodo"] = 503
    r = ti.update()
    res = {f["name"]: f for f in r["feeds"]}
    assert res["feodo"]["result"] == "failed" and "503" in res["feodo"]["why"]
    assert res["firehol_level1"]["result"] == "updated" and r["ok"]
    feeds.close()
    r = ti.update(force=True)
    assert [f["result"] for f in r["feeds"]] == ["failed", "failed"]           # no exception escaped, old copy still usable
    assert ti.load().match(BAD_IP)


def test_etag_makes_the_second_download_a_cheap_no_change(feeds):
    feeds.etags["/firehol"] = '"v1"'
    ti.update()
    r = ti.update()
    assert {f["name"]: f["result"] for f in r["feeds"]}["firehol_level1"] == "unchanged"
    assert ("/firehol", '"v1"') in feeds.hits
    assert ti.load().match(BAD_IP)
    ti.update(force=True)                                            # force ignores the etag
    assert [h for h in feeds.hits if h[0] == "/firehol"][-1][1] is None


def test_oversized_lists_are_refused(feeds, monkeypatch):
    monkeypatch.setattr(ti, "MAX_BYTES", 10)
    r = ti.update()
    assert not r["ok"] and all("large" in f["why"] for f in r["feeds"])
    assert ti.load() is None


def test_only_https_and_known_hosts_are_allowed_by_default(monkeypatch):
    monkeypatch.delenv("LG_THREAT_ALLOW_LOCAL", raising=False)
    assert ti.fetch("http://raw.githubusercontent.com/x", "")[0].startswith("error")
    assert ti.fetch("https://evil.example.com/list.txt", "")[0].startswith("error")
    assert ti.fetch("http://127.0.0.1:1/x", "")[0].startswith("error")
    assert ti.fetch("file:///etc/passwd", "")[0].startswith("error")
    assert ti._url_ok(ti.FEEDS["firehol_level1"]["url"]) and ti._url_ok(ti.FEEDS["feodo"]["url"])


def test_redirects_are_not_followed(feeds):
    """The redirect points at a server that WOULD answer with a valid list, so following it would visibly succeed."""
    target = feeds.url("firehol")

    class R(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), R)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        status, text, _ = ti.fetch(f"http://127.0.0.1:{srv.server_address[1]}/x")
        assert status.startswith("error") and text is None
        assert feeds.hits == []                                    # the redirect target was never contacted
    finally:
        srv.shutdown()
        srv.server_close()


def test_turning_off_forgets_everything(feeds):
    ti.update()
    ti.turn_off()
    assert ti.load() is None and ti.status()["enabled"] is False and not ti.base_dir().exists()


def test_refresh_only_runs_when_enabled_and_due(feeds, monkeypatch):
    monkeypatch.setenv("LG_THREAT_NOW", "1800000000")
    assert ti.refresh_if_due() is None and feeds.hits == []           # never turned on: no network at all
    ti.update()
    n = len(feeds.hits)
    monkeypatch.setenv("LG_THREAT_NOW", str(1800000000 + 3600))
    assert ti.refresh_if_due() is None and len(feeds.hits) == n        # fresh: nothing to do
    monkeypatch.setenv("LG_THREAT_NOW", str(1800000000 + 2 * DAY))
    assert ti.refresh_if_due() is not None and len(feeds.hits) > n     # a day old: refresh


def test_status_reports_stale_lists(feeds, monkeypatch):
    monkeypatch.setenv("LG_THREAT_NOW", "1800000000")
    ti.update()
    monkeypatch.setenv("LG_THREAT_NOW", str(1800000000 + 20 * DAY))
    s = ti.status()
    assert s["level"] == "warning" and "20 days" in s["text"]
    assert sum(f["entries"] for f in s["feeds"]) > 0


def test_corrupt_cache_files_do_not_crash_matching(feeds):
    ti.update()
    ti.feed_path("firehol_level1").write_text("{not json")
    ti.feed_path("feodo").write_text(json.dumps({"ranges": [[1, 2], "junk", [3], ["a", "b"]]}))
    intel = ti.load()
    assert intel is not None and intel.match(BAD_IP) == []


# ------------------------------------------------------- sensor + incident
def test_sensor_flags_a_known_bad_address_even_while_learning(box, feeds, monkeypatch):
    ti.update()
    add_proc(box, 50, "/usr/bin/firefox", ["firefox"])
    (box / "ss.out").write_text(ss_line("firefox", 50, GOOD_IP, 443) + ss_line("firefox", 50, BAD_IP, 443))
    sn.run_once()                                                      # very first run: still learning
    [e] = sensor_events(box)
    assert e["event"] == "threat_intel_hit" and e["severity"] == "critical"
    assert BAD_IP in e["message"] and "FireHOL" in e["message"] and e["remote"] == BAD_IP and e["lists"] == ["firehol_level1"]
    assert BAD_IP in e["entity"] and "/usr/bin/firefox" in e["entity"] and e["technique"] == "T1071"


def test_sensor_flags_it_even_for_an_allow_listed_program(box, feeds, monkeypatch):
    ti.update()
    sn.allow_path_entry("/opt/trusted/app")
    add_proc(box, 51, "/opt/trusted/app", ["app"])
    (box / "ss.out").write_text(ss_line("app", 51, FEODO_IP, 443))
    sn.run_once()
    [e] = sensor_events(box)
    assert e["event"] == "threat_intel_hit" and "Feodo" in e["message"]


def test_sensor_is_silent_when_the_feature_is_off(box, feeds, monkeypatch):
    add_proc(box, 52, "/usr/bin/firefox", ["firefox"])
    (box / "ss.out").write_text(ss_line("firefox", 52, BAD_IP, 443))
    sn.run_once()
    assert sensor_events(box) == []
    assert feeds.hits == []                                            # and it never touched the network


def test_hit_is_announced_once_per_day_not_every_run(box, feeds, monkeypatch):
    ti.update()
    add_proc(box, 53, "/usr/bin/firefox", ["firefox"])
    (box / "ss.out").write_text(ss_line("firefox", 53, BAD_IP, 443))
    sn.run_once()
    at(monkeypatch, 600)
    sn.run_once()
    assert len(sensor_events(box)) == 1
    at(monkeypatch, 2 * DAY)
    sn.run_once()
    assert len(sensor_events(box)) == 2


def test_local_connections_never_hit_even_if_a_list_contains_private_space(box, feeds, monkeypatch):
    feeds.bodies["/firehol"] = (FIREHOL + "192.168.1.0/24\n").encode()
    ti.update()
    add_proc(box, 54, "/usr/bin/x", ["x"])
    (box / "ss.out").write_text(ss_line("x", 54, "192.168.1.9", 443))
    sn.run_once()
    assert sensor_events(box) == []


def test_a_hit_becomes_its_own_critical_incident_with_a_plain_story(box, feeds, monkeypatch):
    ti.update()
    add_proc(box, 55, "/usr/bin/firefox", ["firefox"])
    (box / "ss.out").write_text(ss_line("firefox", 55, BAD_IP, 443))
    sn.run_once()
    [inc] = incidents.build(days=7, directory=box / "lg" / "incidents", now=time.time() + 60)
    assert inc.title == "A program is connected to an address on a public blocklist"
    assert inc.severity == "critical" and BAD_IP in inc.entities
    assert "false positives" in inc.benign


def test_sensor_status_includes_threat_intel(box, feeds):
    assert sn.status()["threat_intel"]["enabled"] is False
    ti.update()
    assert sn.status()["threat_intel"]["level"] == "ok"


def test_cli_status_check_and_off(feeds, capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["threat_intel.py", "--update", "--json"])
    assert ti.main() == 0
    monkeypatch.setattr(sys, "argv", ["threat_intel.py", "--check", BAD_IP, "--json"])
    capsys.readouterr()
    assert ti.main() == 0 and json.loads(capsys.readouterr().out) == ["firehol_level1"]
    monkeypatch.setattr(sys, "argv", ["threat_intel.py", "--off"])
    assert ti.main() == 0
    monkeypatch.setattr(sys, "argv", ["threat_intel.py", "--check", BAD_IP])
    assert ti.main() == 1

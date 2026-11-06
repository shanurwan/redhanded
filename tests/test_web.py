import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from http.server import ThreadingHTTPServer

import pytest

from redhanded.runner import Report, ScanConfig
from redhanded.service import Cache, Service
from redhanded.spend import GuardDecision, GuardState, StateFile
from redhanded.web import RateLimit, Scanner, WebConfig, list_replays, make_handler, resolve_spec

SCAN_ID = "rh-20261104-150536-8193e9"


def write_scan(root, scan_id=SCAN_ID, package="rh-zoo-network-tool", verdict="HIGH", meta=None):
    d = root / scan_id
    (d / "log").mkdir(parents=True)
    r = Report(scan_id=scan_id, package=package, version="1.0.0", integrity="sha512-abc", verdict=verdict,
               reasons=["HIGH: spawned wget"], container_aware=False, seconds=4.6,
               evidence={"execs": [[["wget", "http://update.rh-zoo.invalid/ping"], True]]}, sandbox={})
    (d / "report.json").write_text(json.dumps(asdict(r)))
    (d / "capture.jsonl").write_text(json.dumps({"kind": "http", "at": 1.0, "peer": "x", "host": "update.rh-zoo.invalid",
                                                 "detail": "GET /ping", "headers": {}, "data": ""}) + "\n")
    (d / "log" / "runsc.boot.txt").write_text("I1104 X execve(...) = 0\n")
    if meta:
        (d / "meta.json").write_text(json.dumps(meta))
    return r


def set_guard(path, state=GuardState.OK, at=None):
    StateFile(str(path)).write(GuardDecision(state, 0.0, "test"), at or time.time())


@pytest.fixture
def site(tmp_path):
    replays, scans, zoo = tmp_path / "replays", tmp_path / "scans", tmp_path / "zoo"
    write_scan(replays, meta={"title": "Network tool", "summary": "wget in postinstall", "order": 1})
    (zoo / "network-tool").mkdir(parents=True)
    (zoo / "network-tool" / "package.json").write_text('{"name": "rh-zoo-network-tool", "version": "1.0.0"}')
    cfg = WebConfig(data_dir=str(tmp_path), replays_dir=str(replays), zoo_dir=str(zoo),
                    guard_state=str(tmp_path / "guard.json"), host_label="test", scans_per_hour=2)
    calls = []

    def fake_scan(name, version, scan_cfg, integrity):
        calls.append(f"{name}@{version}")
        sid = f"rh-20261104-160000-{len(calls):06x}"
        return Report(**{**asdict(write_scan(scans, sid, name, "CLEAN")), "integrity": integrity})

    def fake_local(path, scan_cfg):
        calls.append(f"zoo:{path.name}")
        return write_scan(scans, f"rh-20261104-170000-{len(calls):06x}")

    service = Service(Cache(str(tmp_path / "c.sqlite3")), ScanConfig(scans_dir=str(scans)),
                      scanner=fake_scan, resolve=lambda n, v, r: f"sha512-{n}-{v}")
    scanner = Scanner(cfg, service, None, local_scan=fake_local)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cfg, scanner, RateLimit(cfg.scans_per_hour)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    yield base, scanner, cfg, calls
    server.shutdown()


def get(url):
    try:
        with urllib.request.urlopen(url) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def post(url, body):
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_page_is_served_with_a_strict_policy(site):
    base, *_ = site
    status, headers, body = get(base + "/")
    assert status == 200 and b"RedHanded" in body
    assert "script-src" not in headers["Content-Security-Policy"]          # falls back to 'self': no inline script
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_replays_list_and_view(site):
    base, *_ = site
    _, _, body = get(base + "/api/replays")
    [r] = json.loads(body)
    assert (r["scan_id"], r["verdict"], r["title"]) == (SCAN_ID, "HIGH", "Network tool")
    _, _, body = get(f"{base}/api/scans/{SCAN_ID}")
    view = json.loads(body)
    assert view["report"]["verdict"] == "HIGH"
    assert view["capture"][0]["host"] == "update.rh-zoo.invalid"
    assert "syscalls.log.gz" in view["files"] and "report.json" in view["files"]


@pytest.mark.parametrize("path", [
    "/api/scans/../../etc/passwd", "/api/scans/rh-x/files/report.json",
    f"/api/scans/{SCAN_ID}/files/../report.json", f"/api/scans/{SCAN_ID}/files/meta.json",
    f"/api/scans/{SCAN_ID}/files/%2e%2e%2fsecret",
])
def test_only_known_files_of_known_scans_are_served(site, path):
    base, *_ = site
    assert get(base + path)[0] == 404


def test_full_syscall_log_downloads_gzipped(site):
    import gzip
    base, *_ = site
    status, headers, body = get(f"{base}/api/scans/{SCAN_ID}/files/syscalls.log.gz")
    assert status == 200 and headers["Content-Type"] == "application/gzip"
    assert gzip.decompress(body).startswith(b"I1104 X execve")


def test_scans_fail_closed_without_a_fresh_guard_state(site, tmp_path):
    base, scanner, cfg, calls = site
    assert post(base + "/api/scan", {"package": "left-pad@1.3.0"})[0] == 503      # no guard file at all
    set_guard(cfg.guard_state, at=time.time() - 7200)                             # stale
    assert post(base + "/api/scan", {"package": "left-pad@1.3.0"})[0] == 503
    set_guard(cfg.guard_state, GuardState.PAUSE_ALL)
    assert post(base + "/api/scan", {"package": "left-pad@1.3.0"})[0] == 503
    assert calls == []


def test_live_scan_runs_and_second_is_cached(site):
    base, scanner, cfg, calls = site
    set_guard(cfg.guard_state)
    for expect_cached in (False, True):
        status, body = post(base + "/api/scan", {"package": "left-pad@1.3.0"})
        assert status == 202
        scanner.run_one(scanner._queue.get_nowait())
        _, _, raw = get(f"{base}/api/jobs/{body['job']}")
        job = json.loads(raw)
        assert (job["state"], job["verdict"], job["cached"]) == ("done", "CLEAN", expect_cached)
    assert calls == ["left-pad@1.3.0"]


def test_zoo_sample_runs_and_unknown_sample_is_refused(site):
    base, scanner, cfg, calls = site
    set_guard(cfg.guard_state)
    assert post(base + "/api/scan", {"zoo": "../../etc"})[0] == 400
    status, body = post(base + "/api/scan", {"zoo": "network-tool"})
    assert status == 202
    scanner.run_one(scanner._queue.get_nowait())
    assert scanner.jobs[body["job"]].verdict == "HIGH" and calls == ["zoo:network-tool"]


def test_rate_limit_and_bad_requests(site):
    base, scanner, cfg, calls = site
    set_guard(cfg.guard_state)
    assert post(base + "/api/scan", b"not json")[0] == 400
    assert post(base + "/api/scan", {"package": 5})[0] == 400
    assert post(base + "/api/scan", b"x" * 5000)[0] == 413
    assert [post(base + "/api/scan", {"package": "left-pad@1.3.0"})[0] for _ in range(3)] == [202, 202, 429]


def test_guard_pausing_mid_queue_stops_the_job(site):
    base, scanner, cfg, calls = site
    set_guard(cfg.guard_state)
    _, body = post(base + "/api/scan", {"package": "left-pad@1.3.0"})
    set_guard(cfg.guard_state, GuardState.PAUSE_ALL)
    scanner.run_one(scanner._queue.get_nowait())
    job = scanner.jobs[body["job"]]
    assert job.state == "error" and "spend guard" in job.error and calls == []


def test_resolve_spec_keeps_exact_versions_offline():
    assert resolve_spec("left-pad@1.3.0", "http://unused") == ("left-pad", "1.3.0")
    assert resolve_spec("@swc/core@1.16.21", "http://unused") == ("@swc/core", "1.16.21")


def test_rate_limit_window_slides():
    now = [0.0]
    rl = RateLimit(1, clock=lambda: now[0])
    assert rl.take("a") and not rl.take("a") and rl.take("b")
    now[0] = 3601
    assert rl.take("a")


def test_replays_sorted_by_order(tmp_path):
    write_scan(tmp_path, "rh-20261104-000000-000002", meta={"title": "B", "order": 2})
    write_scan(tmp_path, "rh-20261104-000000-000001", meta={"title": "A", "order": 1})
    assert [r["title"] for r in list_replays(str(tmp_path))] == ["A", "B"]

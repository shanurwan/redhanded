"""The dependency fetch runs on the host, so what it can reach has to be small and tested."""
import io
import json
import socket
import tarfile
import threading
from pathlib import Path

from redhanded.egress import EgressGate
from redhanded import runner


def _listener():
    srv = socket.create_server(("127.0.0.1", 0))
    hits = []
    def run():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            hits.append(c.recv(16))
            c.sendall(b"pong")
            c.close()
    threading.Thread(target=run, daemon=True).start()
    return srv, srv.getsockname()[1], hits


def _ask(gate, line: bytes) -> bytes:
    host, port = gate.url.rsplit("/", 1)[1].split(":")
    with socket.create_connection((host, int(port)), timeout=5) as s:
        s.sendall(line + b"\r\n\r\n")
        return s.recv(200)


def test_the_gate_tunnels_to_a_listed_host():
    srv, port, hits = _listener()
    with EgressGate({"127.0.0.1"}, port=port) as gate:
        host, gp = gate.url.rsplit("/", 1)[1].split(":")
        with socket.create_connection((host, int(gp)), timeout=5) as s:
            s.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode())
            assert b" 200 " in s.recv(200)
            s.sendall(b"ping")
            assert s.recv(16) == b"pong"
    srv.close()
    assert hits == [b"ping"] and not gate.refused


def test_the_gate_refuses_everything_else_without_touching_it():
    srv, port, hits = _listener()
    with EgressGate({"registry.npmjs.org"}, port=port) as gate:
        assert b" 403 " in _ask(gate, f"CONNECT 127.0.0.1:{port} HTTP/1.1".encode())
        assert b" 403 " in _ask(gate, f"GET http://127.0.0.1:{port}/a.tgz HTTP/1.1".encode())
        assert b" 403 " in _ask(gate, b"CONNECT registry.npmjs.org:22 HTTP/1.1")
    srv.close()
    assert hits == [] and len(gate.refused) == 3


def test_npm_is_given_the_gate_and_no_git(tmp_path, monkeypatch):
    root = tmp_path / "root"
    for p in ("usr/local/bin/node", "usr/local/lib/node_modules/npm/bin/npm-cli.js"):
        (root / p).parent.mkdir(parents=True, exist_ok=True)
        (root / p).write_text("")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        data = json.dumps({"name": "a", "version": "1.0.0", "dependencies": {"b": "^1.0.0", "evil": "http://x.test/a.tgz"}}).encode()
        info = tarfile.TarInfo("package/package.json")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    seen = {}
    class Done:
        returncode = 0
    def fake_run(cmd, cwd, env, **k):
        seen.update(env=env, manifest=json.loads((Path(cwd) / "package.json").read_text()))
        return Done()
    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    note = runner.fetch_deps(buf.getvalue(), tmp_path / "deps", str(root), "https://registry.npmjs.org")
    assert note == "1 dependencies fetched"
    assert seen["manifest"]["dependencies"] == {"b": "^1.0.0"}
    assert seen["env"]["npm_config_git"] == "/bin/false"
    assert seen["env"]["npm_config_https_proxy"].startswith("http://127.0.0.1:") and seen["env"]["npm_config_ignore_scripts"] == "true"


def test_a_download_is_only_taken_from_the_registry_itself(monkeypatch):
    import pytest
    meta = json.dumps({"dist": {"integrity": "x", "tarball": "http://attacker.test/a.tgz"}}).encode()
    calls = []
    def fake_get(url, limit):
        calls.append(url)
        return meta
    monkeypatch.setattr(runner, "_get", fake_get)
    with pytest.raises(runner.ScanError):
        runner.fetch("a", "1.0.0", "https://registry.npmjs.org")
    assert calls == ["https://registry.npmjs.org/a/1.0.0"]


def test_a_recorded_log_never_keeps_fake_key_text():
    from redhanded.replay import redact
    line = 'read(0xc /home/dev/.ssh/id_ed25519, 0x7f "-----BEGIN OPENSSH PRIVATE KEY-----\\nb3Blbg==\\n"..., 411)'
    out = redact(line, {})
    assert "BEGIN" not in out and "b3Blbg" not in out and "411" in out
    for p in Path("replays").glob("*/syscalls-excerpt.txt"):
        assert "PRIVATE KEY" not in p.read_text(errors="replace"), p

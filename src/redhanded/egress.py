"""The only way out for the dependency fetch, which runs on the host before a package is detonated.

The package's own dependencies are filtered to plain version ranges, but npm follows whatever those
dependencies name in turn, including a URL or a git source. So the fetch goes through this: a forward
proxy that opens a tunnel to the hosts it was given and nothing else. Names it refuses are never looked up.
"""
from __future__ import annotations

import socket
import socketserver
import threading


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        words = self.rfile.readline(8192).decode("latin-1").split()
        while self.rfile.readline(8192) not in (b"\r\n", b"\n", b""):
            pass
        gate: EgressGate = self.server.gate  # type: ignore[attr-defined]
        target = words[1] if len(words) > 1 else ""
        if not words or words[0] != "CONNECT":
            return self._refuse(gate, target)
        host, _, port = target.rpartition(":")
        if host.lower() not in gate.hosts or port != str(gate.port):
            return self._refuse(gate, target)
        try:
            upstream = socket.create_connection((host, gate.port), timeout=20)
        except OSError:
            self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self.wfile.flush()
        self.connection.settimeout(120)
        upstream.settimeout(120)
        threading.Thread(target=_pump, args=(upstream, self.connection), daemon=True).start()
        _pump(self.connection, upstream)

    def _refuse(self, gate: "EgressGate", target: str) -> None:
        gate.refused.add(target[:120])
        self.wfile.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")


def _pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while data := src.recv(65536):
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s, how in ((dst, socket.SHUT_WR), (src, socket.SHUT_RD)):
            try:
                s.shutdown(how)
            except OSError:
                pass


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class EgressGate:
    """`with EgressGate({"registry.npmjs.org"}) as gate:` then point the client at gate.url."""

    def __init__(self, hosts: set[str], port: int = 443):
        self.hosts = {h.lower() for h in hosts}
        self.port = port
        self.refused: set[str] = set()
        self._server = _Server(("127.0.0.1", 0), _Handler)
        self._server.gate = self  # type: ignore[attr-defined]
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"

    def __enter__(self) -> "EgressGate":
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()

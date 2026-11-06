"""The fake internet a sandbox sees.

DNS answers every name with an address of its own from a private range, so
a later connect to that address names the host it was meant for. Every TCP
connection lands on one catch-all listener that records what was sent:
HTTP requests in full, the server name from a TLS ClientHello, raw bytes
otherwise. Nothing is ever forwarded; the sinkhole has no upstream.
"""
from __future__ import annotations

import asyncio
import hashlib
import base64
import ipaddress
import json
import subprocess
import ssl
import re
import struct
import time
from pathlib import Path
from dataclasses import dataclass, field

MAX_CAPTURE = 1 << 20          # bytes kept per connection
READ_TIMEOUT = 5.0
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}


class NamePool:
    """One stable private address per name, and back again."""

    def __init__(self, network: str = "10.66.0.0/16"):
        self._hosts = ipaddress.ip_network(network).hosts()
        for _ in range(9):          # leave .1-.9 for the gateway and the sinkhole itself
            next(self._hosts)
        self._by_name: dict[str, str] = {}
        self._by_ip: dict[str, str] = {}

    def address(self, name: str) -> str:
        name = name.rstrip(".").lower()
        ip = self._by_name.get(name)
        if ip is None:
            ip = str(next(self._hosts))
            self._by_name[name] = ip
            self._by_ip[ip] = name
        return ip

    def name_of(self, ip: str) -> str | None:
        return self._by_ip.get(ip)

    @classmethod
    def from_records(cls, records: list["Record"]) -> "NamePool":
        """Rebuild the name map from DNS answers the sinkhole recorded."""
        pool = cls()
        for r in records:
            ip = r.headers.get("answer") if r.kind == "dns" else None
            if ip:
                pool._by_name.setdefault(r.host, ip)
                pool._by_ip.setdefault(ip, r.host)
        return pool


@dataclass
class Record:
    kind: str                  # dns | http | tls | raw
    at: float
    peer: str
    host: str = ""             # qname, Host header or SNI
    detail: str = ""           # qtype, "METHOD path", or local port
    headers: dict[str, str] = field(default_factory=dict)
    data: bytes = b""

    def to_json(self) -> str:
        return json.dumps({"kind": self.kind, "at": self.at, "peer": self.peer, "host": self.host,
                           "detail": self.detail, "headers": self.headers,
                           "data": base64.b64encode(self.data).decode()})

    @classmethod
    def from_json(cls, line: str) -> "Record":
        d = json.loads(line)
        d["data"] = base64.b64decode(d["data"])
        return cls(**d)


class Capture:
    def __init__(self, path: str | None = None):
        self.records: list[Record] = []
        self._file = open(path, "a", encoding="utf-8") if path else None

    def add(self, rec: Record) -> None:
        self.records.append(rec)
        if self._file:
            self._file.write(rec.to_json() + "\n")
            self._file.flush()

    def close(self) -> None:
        if self._file:
            self._file.close()


# ---------------------------------------------------------------- DNS

def _read_qname(msg: bytes, off: int) -> tuple[str, int]:
    labels = []
    while True:
        n = msg[off]
        if n == 0:
            return ".".join(labels), off + 1
        if n & 0xC0:
            raise ValueError("compressed name in question")
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n


def dns_answer(query: bytes, pool: NamePool) -> tuple[bytes, str, str]:
    """Build the reply. Returns (reply, qname, qtype)."""
    qid, flags, qdcount = struct.unpack("!HHH", query[:6])
    if qdcount < 1:
        raise ValueError("no question")
    qname, off = _read_qname(query, 12)
    qtype, qclass = struct.unpack("!HH", query[off:off + 4])
    question = query[12:off + 4]
    rd = flags & 0x0100
    answers = b""
    ancount = 0
    if qtype == 1 and qname:
        ip = ipaddress.ip_address(pool.address(qname)).packed
        answers = b"\xc0\x0c" + struct.pack("!HHIH", 1, qclass, 60, 4) + ip
        ancount = 1
    # Other types get an empty NOERROR answer: the name exists, nothing more.
    header = struct.pack("!HHHHHH", qid, 0x8000 | 0x0400 | rd | 0x0080, 1, ancount, 0, 0)
    return header + question + answers, qname.lower(), QTYPES.get(qtype, str(qtype))


class _DnsProtocol(asyncio.DatagramProtocol):
    def __init__(self, pool: NamePool, capture: Capture):
        self.pool, self.capture = pool, capture

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            reply, qname, qtype = dns_answer(data, self.pool)
        except (ValueError, struct.error, IndexError):
            self.capture.add(Record("dns", time.time(), addr[0], detail="malformed", data=data[:512]))
            return
        answer = {"answer": self.pool.address(qname)} if qtype == "A" and qname else {}
        self.capture.add(Record("dns", time.time(), addr[0], host=qname, detail=qtype, headers=answer))
        self.transport.sendto(reply, addr)


# ---------------------------------------------------------------- TCP

def tls_server_name(hello: bytes) -> str | None:
    """The SNI from a TLS ClientHello, without decrypting anything."""
    try:
        if hello[0] != 0x16 or hello[5] != 0x01:
            return None
        p = 9 + 2 + 32                         # record + handshake headers, version, random
        p += 1 + hello[p]                      # session id
        p += 2 + struct.unpack("!H", hello[p:p + 2])[0]   # cipher suites
        p += 1 + hello[p]                      # compression methods
        end = p + 2 + struct.unpack("!H", hello[p:p + 2])[0]
        p += 2
        while p + 4 <= end:
            etype, elen = struct.unpack("!HH", hello[p:p + 4])
            if etype == 0:
                q = p + 4 + 2                  # server name list length
                if hello[q] == 0:
                    n = struct.unpack("!H", hello[q + 1:q + 3])[0]
                    return hello[q + 3:q + 3 + n].decode("ascii", "replace").lower()
            p += 4 + elen
    except (IndexError, struct.error):
        return None
    return None


_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ", b"OPTIONS ")


async def _read_http(first: bytes, reader: asyncio.StreamReader) -> tuple[str, dict[str, str], bytes]:
    buf = first
    while b"\r\n\r\n" not in buf and len(buf) < MAX_CAPTURE:
        chunk = await asyncio.wait_for(reader.read(65536), READ_TIMEOUT)
        if not chunk:
            break
        buf += chunk
    head, _, body = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        k, sep, v = line.partition(":")
        if sep:
            headers[k.strip().lower()] = v.strip()
    want = min(int(headers.get("content-length", "0") or 0), MAX_CAPTURE)
    chunked = "chunked" in headers.get("transfer-encoding", "").lower()
    while (len(body) < want or (chunked and not body.endswith(b"0\r\n\r\n"))) and len(body) < MAX_CAPTURE:
        chunk = await asyncio.wait_for(reader.read(65536), READ_TIMEOUT)
        if not chunk:
            break
        body += chunk
    request_line = " ".join(lines[0].split(" ")[:2])
    return request_line, headers, body[:MAX_CAPTURE]


METADATA_IP = "169.254.169.254"
_HOSTNAME = re.compile(r"^[a-z0-9._-]{1,253}$")
# Enough of the real answers that a credential stealer carries on and shows what it wants.
_FAKE_API = {("api.github.com", "GET /user"): b'{"login":"dev-user","id":4242,"type":"User"}',
             ("registry.npmjs.org", "GET /-/whoami"): b'{"username":"dev-user"}',
             ("github.com", "GET /user"): b'{"login":"dev-user","id":4242}'}


# Real downloads the fake internet can answer, because attacks stop without them. The 2026 npm
# worms fetch Bun from GitHub to run their payload, and quit without acting if the fetch fails.
_MIRRORED = re.compile(r"^GET /oven-sh/bun/releases/download/bun-v[0-9.]+/(bun-linux-x64(?:-baseline)?)\.zip$")


def mirrored_file(host: str, line: str, mirror: str | None) -> Path | None:
    if not mirror or host.split(":", 1)[0] not in ("github.com", "objects.githubusercontent.com"):
        return None
    m = _MIRRORED.match(line)
    path = Path(mirror) / f"{m.group(1)}.zip" if m else None
    return path if path and path.is_file() else None


def make_ca(directory: Path) -> Path:
    """A root certificate for one scan. Its key never enters the sandbox."""
    directory.mkdir(parents=True, exist_ok=True)
    key, crt = directory / "ca.key", directory / "ca.crt"
    run = lambda *a: subprocess.run(a, check=True, capture_output=True, timeout=20)
    run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
    run("openssl", "req", "-x509", "-new", "-key", str(key), "-sha256", "-days", "30", "-subj", "/O=Corp IT/CN=Corp Root CA", "-out", str(crt))
    run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(directory / "leaf.key"))
    return crt


class CertForge:
    """Answers HTTPS for any name the sandbox asks for, signed by the scan's root."""

    def __init__(self, directory: str | Path):
        self.dir = Path(directory)
        self._contexts: dict[str, ssl.SSLContext] = {}
        self.server = self._context("localhost")
        self.server.sni_callback = self._on_sni

    def _context(self, host: str) -> ssl.SSLContext:
        if host in self._contexts:
            return self._contexts[host]
        name = hashlib.sha256(host.encode()).hexdigest()[:16]
        csr, crt, ext = self.dir / f"{name}.csr", self.dir / f"{name}.crt", self.dir / f"{name}.ext"
        ext.write_text(f"subjectAltName=DNS:{host}\n")
        run = lambda *a: subprocess.run(a, check=True, capture_output=True, timeout=20)
        run("openssl", "req", "-new", "-key", str(self.dir / "leaf.key"), "-subj", "/O=Corp IT/CN=sandbox", "-out", str(csr))
        run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(self.dir / "ca.crt"), "-CAkey", str(self.dir / "ca.key"), "-CAcreateserial",
            "-days", "30", "-sha256", "-extfile", str(ext), "-out", str(crt))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(crt), str(self.dir / "leaf.key"))
        ctx.set_alpn_protocols(["http/1.1"])
        self._contexts[host] = ctx
        return ctx

    def _on_sni(self, sslobj, servername, _ctx):
        if servername and _HOSTNAME.match(servername.lower()):
            try:
                sslobj.context = self._context(servername.lower())
            except (subprocess.SubprocessError, OSError, ssl.SSLError):
                pass


class _TlsStream:
    """TLS over the streams we already have, because the ClientHello was read before we knew it was TLS."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ctx: ssl.SSLContext, first: bytes):
        self.reader, self.writer = reader, writer
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.obj = ctx.wrap_bio(self.incoming, self.outgoing, server_side=True)
        self.incoming.write(first)

    async def _flush(self) -> None:
        data = self.outgoing.read()
        if data:
            self.writer.write(data)
            await self.writer.drain()

    async def _more(self) -> bool:
        await self._flush()
        chunk = await asyncio.wait_for(self.reader.read(65536), READ_TIMEOUT)
        if not chunk:
            return False
        self.incoming.write(chunk)
        return True

    async def handshake(self) -> None:
        while True:
            try:
                self.obj.do_handshake()
                await self._flush()
                return
            except ssl.SSLWantReadError:
                if not await self._more():
                    raise ConnectionError("closed during handshake") from None

    async def read(self, n: int) -> bytes:
        while True:
            try:
                return self.obj.read(n)
            except ssl.SSLWantReadError:
                if not await self._more():
                    return b""
            except ssl.SSLZeroReturnError:
                return b""

    async def write(self, data: bytes) -> None:
        self.obj.write(data)
        await self._flush()


class Sinkhole:
    def __init__(self, capture: Capture, pool: NamePool | None = None, metadata: dict | None = None,
                 forge: "CertForge | None" = None, mirror: str | None = None):
        self.capture = capture
        self.mirror = mirror
        self.forge = forge            # with it, HTTPS is answered and read instead of closed
        self.pool = pool or NamePool()
        self.metadata = metadata      # decoy cloud credentials served at the metadata address
        self._servers: list = []

    def _http_body(self, host: str, line: str) -> bytes:
        if self.metadata and host.split(":", 1)[0] == METADATA_IP and "/security-credentials" in line:
            if line.rstrip("/").endswith("/security-credentials"):
                return b"redhanded-scan-role"
            return json.dumps(self.metadata).encode()
        return _FAKE_API.get((host.split(":", 1)[0], line), b"{}")

    async def _answer_http(self, first: bytes, reader, send, peer: str, default_host: str = "") -> None:
        line, headers, body = await _read_http(first, reader)
        host = headers.get("host", "") or default_host
        self.capture.add(Record("http", time.time(), peer, host, line, headers, body))
        real = mirrored_file(host, line, self.mirror)
        reply = real.read_bytes() if real else self._http_body(host, line)
        kind = b"application/zip" if real else b"application/json"
        await send(b"HTTP/1.1 200 OK\r\nContent-Type: " + kind + b"\r\nContent-Length: "
                   + str(len(reply)).encode() + b"\r\nConnection: close\r\n\r\n" + reply)

    async def _on_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")[0]
        port = str(writer.get_extra_info("sockname")[1])
        try:
            first = await asyncio.wait_for(reader.read(65536), READ_TIMEOUT)
            if first.startswith(_HTTP_METHODS):
                async def send(data: bytes) -> None:
                    writer.write(data)
                    await writer.drain()
                await self._answer_http(first, reader, send, peer)
            elif first[:1] == b"\x16":
                sni = tls_server_name(first) or ""
                self.capture.add(Record("tls", time.time(), peer, sni, port, data=first))
                if self.forge:
                    stream = _TlsStream(reader, writer, self.forge.server, first)
                    await stream.handshake()
                    plain = await stream.read(65536)
                    if plain.startswith(_HTTP_METHODS):
                        await self._answer_http(plain, stream, stream.write, peer, sni)
                    elif plain:
                        self.capture.add(Record("raw", time.time(), peer, sni, port, data=plain[:MAX_CAPTURE]))
            else:
                data = first
                while first and len(data) < MAX_CAPTURE:
                    first = await asyncio.wait_for(reader.read(65536), READ_TIMEOUT)
                    data += first
                self.capture.add(Record("raw", time.time(), peer, "", port, data=data[:MAX_CAPTURE]))
        except (asyncio.TimeoutError, ConnectionError, ValueError, ssl.SSLError):
            pass      # a client that rejects our certificate still left its server name above
        finally:
            writer.close()

    async def start(self, host: str, dns_port: int, tcp_ports: list[int], dns_host: str | None = None) -> list[int]:
        """Start listening. Returns the bound ports, DNS first (useful with port 0).

        Bind DNS to the resolver's own address: a UDP socket on 0.0.0.0 replies
        from the interface address, and resolvers drop replies from the wrong server.
        """
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DnsProtocol(self.pool, self.capture), local_addr=(dns_host or host, dns_port))
        self._servers.append(transport)
        bound = [transport.get_extra_info("sockname")[1]]
        for port in tcp_ports:
            server = await asyncio.start_server(self._on_tcp, host, port)
            self._servers.append(server)
            bound.append(server.sockets[0].getsockname()[1])
        return bound

    async def stop(self) -> None:
        for s in self._servers:
            s.close()
        self._servers.clear()


DEFAULT_TCP_PORTS = [21, 22, 25, 80, 443, 1080, 3000, 4444, 5000, 8000, 8080, 8443, 8888, 9000, 9999]


def main(argv: list[str] | None = None) -> int:
    """Run a sinkhole until SIGTERM. The runner starts this inside the sinkhole netns."""
    import argparse
    import signal

    p = argparse.ArgumentParser(prog="redhanded.sinkhole")
    p.add_argument("--capture", required=True)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--dns-host", default="10.66.0.1")
    p.add_argument("--metadata", help="JSON file with decoy cloud credentials")
    p.add_argument("--ready", help="file to create once listening")
    p.add_argument("--mirror", help="folder of real downloads the fake internet may serve")
    p.add_argument("--tls-dir", help="folder with this scan's root certificate; answers HTTPS when given")
    args = p.parse_args(argv)

    metadata = None
    if args.metadata:
        with open(args.metadata, encoding="utf-8") as f:
            metadata = json.load(f)

    async def run() -> None:
        capture = Capture(args.capture)
        forge = None
        if args.tls_dir:
            try:
                forge = CertForge(args.tls_dir)
            except (subprocess.SubprocessError, OSError, ssl.SSLError):
                forge = None     # HTTPS falls back to server names only
        sink = Sinkhole(capture, metadata=metadata, forge=forge, mirror=args.mirror)
        await sink.start(args.host, 53, DEFAULT_TCP_PORTS, dns_host=args.dns_host)
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGTERM, stop.set)
        loop.add_signal_handler(signal.SIGINT, stop.set)
        if args.ready:
            open(args.ready, "w").close()
        await stop.wait()
        await sink.stop()
        capture.close()

    asyncio.run(run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

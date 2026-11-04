"""The fake internet a sandbox sees.

DNS answers every name with an address of its own from a private range, so
a later connect to that address names the host it was meant for. Every TCP
connection lands on one catch-all listener that records what was sent:
HTTP requests in full, the server name from a TLS ClientHello, raw bytes
otherwise. Nothing is ever forwarded; the sinkhole has no upstream.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import struct
import time
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
        self.capture.add(Record("dns", time.time(), addr[0], host=qname, detail=qtype))
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
    while len(body) < want:
        chunk = await asyncio.wait_for(reader.read(65536), READ_TIMEOUT)
        if not chunk:
            break
        body += chunk
    request_line = " ".join(lines[0].split(" ")[:2])
    return request_line, headers, body[:MAX_CAPTURE]


class Sinkhole:
    def __init__(self, capture: Capture, pool: NamePool | None = None):
        self.capture = capture
        self.pool = pool or NamePool()
        self._servers: list = []

    async def _on_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")[0]
        port = str(writer.get_extra_info("sockname")[1])
        try:
            first = await asyncio.wait_for(reader.read(65536), READ_TIMEOUT)
            if first.startswith(_HTTP_METHODS):
                line, headers, body = await _read_http(first, reader)
                self.capture.add(Record("http", time.time(), peer, headers.get("host", ""), line, headers, body))
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             b"Content-Length: 2\r\nConnection: close\r\n\r\n{}")
                await writer.drain()
            elif first[:1] == b"\x16":
                self.capture.add(Record("tls", time.time(), peer, tls_server_name(first) or "", port, data=first))
            else:
                data = first
                while first and len(data) < MAX_CAPTURE:
                    first = await asyncio.wait_for(reader.read(65536), READ_TIMEOUT)
                    data += first
                self.capture.add(Record("raw", time.time(), peer, "", port, data=data[:MAX_CAPTURE]))
        except (asyncio.TimeoutError, ConnectionError, ValueError):
            pass
        finally:
            writer.close()

    async def start(self, host: str, dns_port: int, tcp_ports: list[int]) -> list[int]:
        """Start listening. Returns the bound ports, DNS first (useful with port 0)."""
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DnsProtocol(self.pool, self.capture), local_addr=(host, dns_port))
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

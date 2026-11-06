import asyncio
import socket
import ssl
import struct

import pytest

from redhanded.sinkhole import Capture, NamePool, Record, Sinkhole, dns_answer, tls_server_name


def dns_query(name: str, qtype: int = 1, qid: int = 0x1234) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def test_pool_gives_each_name_a_stable_address():
    pool = NamePool()
    a = pool.address("registry.npmjs.org")
    assert pool.address("REGISTRY.npmjs.org.") == a
    assert pool.address("example.invalid") != a
    assert pool.name_of(a) == "registry.npmjs.org"
    assert a == "10.66.0.10"            # .1-.9 stay reserved


def test_dns_a_answer_points_into_the_pool():
    pool = NamePool()
    reply, qname, qtype = dns_answer(dns_query("cdn.example.invalid"), pool)
    assert (qname, qtype) == ("cdn.example.invalid", "A")
    qid, flags, qd, an = struct.unpack("!HHHH", reply[:8])
    assert qid == 0x1234 and flags & 0x8000 and an == 1
    assert socket.inet_ntoa(reply[-4:]) == pool.address("cdn.example.invalid")


def test_dns_other_types_answer_empty():
    reply, _, qtype = dns_answer(dns_query("x.example.invalid", qtype=16), NamePool())
    assert qtype == "TXT"
    assert struct.unpack("!H", reply[6:8])[0] == 0


def test_dns_rejects_garbage():
    with pytest.raises((ValueError, struct.error, IndexError)):
        dns_answer(b"\x00\x01", NamePool())


def test_record_round_trips_through_json():
    r = Record("http", 1.0, "10.66.0.2", "h.example.invalid", "POST /x", {"a": "b"}, b"\x00\xffbody")
    assert Record.from_json(r.to_json()) == r


def run(coro):
    return asyncio.run(coro)


async def _with_sinkhole(fn):
    cap = Capture()
    sink = Sinkhole(cap)
    dns_port, tcp_port = await sink.start("127.0.0.1", 0, [0])
    try:
        await fn(dns_port, tcp_port)
        await asyncio.sleep(0.05)
    finally:
        await sink.stop()
    return cap.records


def test_dns_over_udp_is_answered_and_recorded():
    async def client(dns_port, _):
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        await loop.sock_sendto(sock, dns_query("api.example.invalid"), ("127.0.0.1", dns_port))
        data = await asyncio.wait_for(loop.sock_recv(sock, 512), 2)
        sock.close()
        assert struct.unpack("!H", data[6:8])[0] == 1

    recs = run(_with_sinkhole(client))
    assert [(r.kind, r.host, r.detail) for r in recs] == [("dns", "api.example.invalid", "A")]


def test_http_request_recorded_with_headers_and_body():
    async def client(_, port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        body = b'{"hello": "world"}'
        writer.write(b"POST /collect HTTP/1.1\r\nHost: up.example.invalid\r\nX-Note: n1\r\n"
                     b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(), 2)
        writer.close()
        assert resp.startswith(b"HTTP/1.1 200 OK")

    [rec] = run(_with_sinkhole(client))
    assert (rec.kind, rec.host, rec.detail) == ("http", "up.example.invalid", "POST /collect")
    assert rec.headers["x-note"] == "n1" and rec.data == b'{"hello": "world"}'


def test_tls_hello_reveals_server_name_without_decrypting():
    async def client(_, port):
        ctx = ssl.create_default_context()
        with pytest.raises((ssl.SSLError, ConnectionError, asyncio.IncompleteReadError, OSError)):
            await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port, ssl=ctx, server_hostname="files.example.invalid"), 2)

    [rec] = run(_with_sinkhole(client))
    assert (rec.kind, rec.host) == ("tls", "files.example.invalid")
    assert tls_server_name(rec.data) == "files.example.invalid"


def test_raw_tcp_bytes_recorded():
    async def client(_, port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"\x01\x02plain bytes")
        await writer.drain()
        writer.write_eof()
        await asyncio.wait_for(reader.read(), 2)
        writer.close()

    [rec] = run(_with_sinkhole(client))
    assert rec.kind == "raw" and rec.data == b"\x01\x02plain bytes"


def test_dns_answers_are_recorded_and_rebuild_the_pool():
    async def client(dns_port, _):
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        await loop.sock_sendto(sock, dns_query("one.example.invalid"), ("127.0.0.1", dns_port))
        await asyncio.wait_for(loop.sock_recv(sock, 512), 2)
        sock.close()

    recs = run(_with_sinkhole(client))
    pool = NamePool.from_records(recs)
    assert pool.name_of(recs[0].headers["answer"]) == "one.example.invalid"


def test_metadata_address_serves_decoy_credentials():
    async def go():
        cap = Capture()
        sink = Sinkhole(cap, metadata={"AccessKeyId": "ASIADECOY"})
        _, port = await sink.start("127.0.0.1", 0, [0])
        out = []
        for path in ("/latest/meta-data/iam/security-credentials/", "/latest/meta-data/iam/security-credentials/r"):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(f"GET {path} HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n".encode())
            await writer.drain()
            out.append(await asyncio.wait_for(reader.read(), 2))
            writer.close()
        await sink.stop()
        return out

    role, creds = run(go())
    assert role.endswith(b"redhanded-scan-role")
    assert creds.endswith(b'{"AccessKeyId": "ASIADECOY"}')


def test_https_is_read_when_the_sandbox_trusts_the_scan_root(tmp_path):
    import asyncio, shutil, ssl, urllib.request
    import pytest
    from redhanded.sinkhole import Capture, CertForge, Sinkhole, make_ca
    if not shutil.which("openssl"):
        pytest.skip("no openssl")
    ca = make_ca(tmp_path)

    async def run():
        cap = Capture()
        sink = Sinkhole(cap, forge=CertForge(tmp_path))
        ports = await sink.start("127.0.0.1", 0, [0])

        def client():
            ctx = ssl.create_default_context(cafile=str(ca))
            sock_ctx = ctx
            import http.client
            class Conn(http.client.HTTPSConnection):
                def connect(self):
                    import socket
                    raw = socket.create_connection(("127.0.0.1", ports[1]))
                    self.sock = sock_ctx.wrap_socket(raw, server_hostname="api.github.com")
            c = Conn("api.github.com")
            c.request("GET", "/user", headers={"Authorization": "token bait-value"})
            return c.getresponse().read()

        body = await asyncio.get_running_loop().run_in_executor(None, client)
        await sink.stop()
        return cap, body

    cap, body = asyncio.run(run())
    assert b"dev-user" in body
    http = [r for r in cap.records if r.kind == "http"]
    assert http and http[0].host == "api.github.com" and http[0].headers["authorization"] == "token bait-value"
    assert any(r.kind == "tls" and r.host == "api.github.com" for r in cap.records)


def test_a_client_that_rejects_our_certificate_still_leaves_its_server_name(tmp_path):
    import asyncio, shutil, socket, ssl
    import pytest
    from redhanded.sinkhole import Capture, CertForge, Sinkhole, make_ca
    if not shutil.which("openssl"):
        pytest.skip("no openssl")
    make_ca(tmp_path)

    async def run():
        cap = Capture()
        sink = Sinkhole(cap, forge=CertForge(tmp_path))
        ports = await sink.start("127.0.0.1", 0, [0])

        def client():
            ctx = ssl.create_default_context()
            raw = socket.create_connection(("127.0.0.1", ports[1]))
            with pytest.raises(ssl.SSLError):
                ctx.wrap_socket(raw, server_hostname="pinned.example.invalid")

        await asyncio.get_running_loop().run_in_executor(None, client)
        await sink.stop()
        return cap

    assert any(r.kind == "tls" and r.host == "pinned.example.invalid" for r in asyncio.run(run()).records)

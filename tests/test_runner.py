import base64
import hashlib
import io
import json
import tarfile

import pytest

from redhanded.honeytokens import HoneytokenSet
from redhanded.runner import ScanError, check_integrity, prepare, safe_unpack


def tgz(entries):
    """entries: list of (name, bytes | None for dir | ('sym', target))."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            if content is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif isinstance(content, tuple):
                info.type = tarfile.SYMTYPE
                info.linkname = content[1]
                tar.addfile(info)
            else:
                info.size = len(content)
                info.mode = 0o644
                tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def integrity(data):
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def test_integrity_must_match():
    data = b"tarball"
    check_integrity(data, integrity(data))
    with pytest.raises(ScanError):
        check_integrity(b"other", integrity(data))
    with pytest.raises(ScanError):
        check_integrity(data, "sha1-" + base64.b64encode(hashlib.sha1(data).digest()).decode())


def test_unpack_strips_top_folder(tmp_path):
    n = safe_unpack(tgz([("package/package.json", b"{}"), ("package/lib/a.js", b"x")]), tmp_path)
    assert n == 2
    assert (tmp_path / "package.json").read_bytes() == b"{}"
    assert (tmp_path / "lib" / "a.js").exists()


@pytest.mark.parametrize("name", ["package/../../escape.js", "package//etc/x"])
def test_unpack_rejects_escapes(tmp_path, name):
    with pytest.raises(ScanError):
        safe_unpack(tgz([(name, b"x")]), tmp_path / "dest")
    assert not (tmp_path / "escape.js").exists()


def test_unpack_never_extracts_links(tmp_path):
    safe_unpack(tgz([("package/link", ("sym", "/etc/passwd")), ("package/a.js", b"x")]), tmp_path)
    assert not (tmp_path / "link").exists() and (tmp_path / "a.js").exists()


def test_prepare_lays_out_scan(tmp_path):
    tokens = HoneytokenSet.generate("s1")
    prepare(tmp_path, "left-pad", "1.3.0", tgz([("package/index.js", b"module.exports=1")]), tokens, "/rootfs")
    assert (tmp_path / "work/node_modules/left-pad/index.js").exists()
    assert (tmp_path / "home/.npmrc").read_text().count(tokens.npm_token) == 1
    spec = json.loads((tmp_path / "bundle/config.json").read_text())
    assert spec["root"]["path"] == "/rootfs"
    assert spec["process"]["args"] == ["/bin/sh", "/work/.rh/run.sh"]
    env = dict(e.split("=", 1) for e in spec["process"]["env"])
    assert env["npm_config_userconfig"] == "/dev/null" and env["AWS_ACCESS_KEY_ID"] == tokens.aws_access_key_id
    assert spec["linux"]["namespaces"][-1]["type"] == "network"
    assert json.loads((tmp_path / "metadata.json").read_text())["AccessKeyId"] == tokens.metadata_access_key_id

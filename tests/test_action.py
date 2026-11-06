import importlib.util
import io
import tarfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("check", Path(__file__).parent.parent / "action" / "check.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def test_pack_uses_npm_layout_and_skips_node_modules(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("")
    with tarfile.open(fileobj=io.BytesIO(check.pack(tmp_path)), mode="r:gz") as tar:
        assert tar.getnames() == ["package/package.json"]


def test_unanswered_scan_fails_closed(monkeypatch):
    monkeypatch.setattr(check, "TIMEOUT_S", 0)
    assert check.wait("http://unused", "job")["state"] == "error"

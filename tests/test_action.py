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


rspec = importlib.util.spec_from_file_location("repair_action", Path(__file__).parent.parent / "action" / "repair.py")
repair_action = importlib.util.module_from_spec(rspec)
rspec.loader.exec_module(repair_action)


def test_fix_pr_body_shows_what_was_added_and_each_step():
    body = repair_action.body_for({"name": "p", "version": "2.0.0"}, {
        "pinned": {"version": "1.9.0", "scan_id": "rh-1"}, "decided_by": "agent",
        "new_in_blocked_version": [{"kind": "install_script", "what": "postinstall"}, {"kind": "domain", "what": "x.dev`"}],
        "steps": [{"tool": "check_version", "args": {"version": "1.9.0"}, "result": {"verdict": "CLEAN"}},
                  {"tool": "pin_version", "args": {"version": "1.9.0"}, "result": {"pinned": "1.9.0"}}]}, "https://rh")
    assert "`p@2.0.0`" in body and "install script: `postinstall`" in body and "`x.dev`" in body
    assert "Ran 1.9.0 in the sandbox: **CLEAN**" in body and "https://rh/#rh-1" in body


def test_repair_does_nothing_without_a_token(monkeypatch, tmp_path):
    monkeypatch.delenv("REDHANDED_TOKEN", raising=False)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setattr("sys.argv", ["repair.py", "https://rh"])
    assert repair_action.main() == 0

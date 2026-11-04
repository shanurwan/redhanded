import asyncio

import pytest

pytest.importorskip("mcp")

from redhanded.mcp_server import build_server  # noqa: E402
from tests.test_service import make  # noqa: E402


def test_tools_are_listed_read_only(tmp_path):
    svc, _ = make(tmp_path, {})
    tools = {t.name: t for t in asyncio.run(build_server(svc).list_tools())}
    assert set(tools) == {"check_package", "check_lockfile_change", "get_scan_report"}
    for t in tools.values():
        assert t.annotations.read_only_hint is True and t.annotations.destructive_hint is False
        assert t.description


def test_check_package_over_mcp(tmp_path):
    svc, calls = make(tmp_path, {"left-pad@1.3.0": "CLEAN"})
    result = asyncio.run(build_server(svc).call_tool("check_package", {"name": "left-pad", "version": "1.3.0"}))
    text = str(result)
    assert calls == ["left-pad@1.3.0"] and "CLEAN" in text and "allow" in text


def test_bad_input_comes_back_as_an_error_not_a_crash(tmp_path):
    svc, calls = make(tmp_path, {})
    result = asyncio.run(build_server(svc).call_tool("check_package", {"name": "left-pad", "version": "^1"}))
    assert calls == [] and "exact version" in str(result)

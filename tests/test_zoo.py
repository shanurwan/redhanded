"""The Zoo itself must be valid: a sample that crashes proves nothing either way."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from redhanded.verdict import Verdict

ZOO = Path(__file__).parent.parent / "zoo"
SAMPLES = sorted(p.parent for p in ZOO.glob("*/expect.json"))


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda p: p.name)
def test_sample_is_well_formed(sample):
    expect = json.loads((sample / "expect.json").read_text())
    assert "min_verdict" in expect or "max_verdict" in expect
    for key in ("min_verdict", "max_verdict"):
        if key in expect:
            Verdict[expect[key]]
    assert expect.get("why"), "every sample says what it tests"
    pkg = json.loads((sample / "package.json").read_text())
    assert pkg["private"] is True and pkg["name"].startswith("rh-zoo-")


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("script", sorted(ZOO.glob("*/*.js")), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_sample_script_parses(script):
    subprocess.run(["node", "--check", str(script)], check=True, capture_output=True)

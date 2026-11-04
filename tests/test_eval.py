import json

from redhanded import eval as ev
from redhanded.verdict import Verdict


def fake_scanner(verdicts):
    def scan(case):
        v = verdicts[case.id]
        if isinstance(v, Exception):
            raise v
        return v, [], 1.0, "scan-" + case.id
    return scan


def zoo(tmp_path, name, expect):
    d = tmp_path / "zoo" / name
    d.mkdir(parents=True)
    (d / "expect.json").write_text(json.dumps(expect))
    return d


def test_load_zoo_splits_samples_and_controls(tmp_path):
    zoo(tmp_path, "a", {"min_verdict": "HIGH", "deadline_s": 20})
    zoo(tmp_path, "b", {"max_verdict": "CLEAN"})
    a, b = ev.load_zoo(tmp_path / "zoo")
    assert (a.kind, a.min_verdict, a.deadline_s) == ("zoo", Verdict.HIGH, 20.0)
    assert (b.kind, b.max_verdict) == ("benign", Verdict.CLEAN)


def test_load_benign_ignores_comments(tmp_path):
    p = tmp_path / "b.txt"
    p.write_text("# header\nlodash@4.18.1   # note\n\nbcrypt@6.0.0\n")
    assert [c.target for c in ev.load_benign(p)] == ["lodash@4.18.1", "bcrypt@6.0.0"]


def test_gate_fails_on_any_miss_and_on_benign_block():
    cases = [ev.Case("zoo/x", "zoo", "x", min_verdict=Verdict.HIGH),
             ev.Case("zoo/y", "zoo", "y", min_verdict=Verdict.HIGH),
             ev.Case("ok@1", "benign", "ok@1", max_verdict=Verdict.REVIEW),
             ev.Case("loud@1", "benign", "loud@1", max_verdict=Verdict.REVIEW)]
    results = ev.run(cases, fake_scanner({"zoo/x": "CRITICAL", "zoo/y": "REVIEW", "ok@1": "REVIEW", "loud@1": "HIGH"}))
    s = ev.summarize(results)
    assert s["malicious"]["caught"] == 1 and s["benign"]["blocking_false_alarms"] == 1
    failures = ev.gate(results, s, {"max_review_rate": 0.2})
    assert "zoo/y: got REVIEW" in failures and "loud@1: got HIGH" in failures
    assert any("review rate" in f for f in failures)          # 1 of 2 benign in REVIEW = 50%


def test_scan_error_is_a_failure_not_a_skip():
    cases = [ev.Case("zoo/x", "zoo", "x", min_verdict=Verdict.HIGH)]
    results = ev.run(cases, fake_scanner({"zoo/x": RuntimeError("runsc missing")}))
    assert results[0].verdict == "ERROR" and not results[0].ok
    assert ev.gate(results, ev.summarize(results), {}) == ["zoo/x: got ERROR (RuntimeError: runsc missing)"]


def test_wilson_bounds_are_honest_about_small_samples():
    lo, hi = ev.wilson(10, 10)
    assert hi == 1.0 and lo < 0.75
    assert ev.wilson(0, 0) == (0.0, 1.0)


def test_report_written(tmp_path):
    results = ev.run([ev.Case("zoo/x", "zoo", "x", min_verdict=Verdict.HIGH)], fake_scanner({"zoo/x": "HIGH"}))
    s = ev.summarize(results)
    ev.write_report(tmp_path / "r.json", results, s, [], {"thresholds": {}})
    d = json.loads((tmp_path / "r.json").read_text())
    assert d["passed"] and d["results"][0]["scan_id"] == "scan-zoo/x"

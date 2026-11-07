import json

import pytest

from redhanded.runner import Report, ScanConfig, ScanError
from redhanded.service import Cache, InputError, Service, validate


def report(name, version, verdict, integrity, n=[0]):
    n[0] += 1
    return Report(scan_id=f"rh-20261104-120000-{n[0]:06x}", package=name, version=version, integrity=integrity,
                  verdict=verdict, reasons=[f"{verdict}: test"] if verdict != "CLEAN" else [],
                  container_aware=False, seconds=1.0)


def make(tmp_path, verdicts):
    calls = []

    def scanner(name, version, cfg, integrity):
        calls.append(f"{name}@{version}")
        return report(name, version, verdicts[f"{name}@{version}"], integrity)

    svc = Service(Cache(str(tmp_path / "c.sqlite3")), ScanConfig(scans_dir=str(tmp_path / "scans")),
                  scanner=scanner, resolve=lambda n, v, r: f"sha512-{n}-{v}")
    return svc, calls


@pytest.mark.parametrize("name,version", [
    ("left-pad", "^1.3.0"), ("left-pad", "latest"), ("../etc", "1.0.0"), ("Left-Pad", "1.0.0"),
    ("@scope/../x", "1.0.0"), ("a" * 215, "1.0.0"),
])
def test_rejects_ranges_tags_and_odd_names(name, version):
    with pytest.raises(InputError):
        validate(name, version)


def test_scoped_and_prerelease_accepted():
    validate("@swc/core", "1.16.21")
    validate("x", "2.0.0-beta.1")


def test_second_check_is_served_from_cache(tmp_path):
    svc, calls = make(tmp_path, {"left-pad@1.3.0": "CLEAN"})
    first = svc.check("left-pad", "1.3.0")
    second = svc.check("left-pad", "1.3.0")
    assert calls == ["left-pad@1.3.0"]
    assert (first["cached"], second["cached"]) == (False, True)
    assert second["verdict"] == "CLEAN" and second["advice"] == "allow"


def test_lookup_only_does_not_scan(tmp_path):
    svc, calls = make(tmp_path, {})
    r = svc.check("left-pad", "1.3.0", scan_if_missing=False)
    assert calls == [] and r["verdict"] is None and r["advice"] == "unknown"


def lock(**pkgs):
    return json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "app"}, **{
        f"node_modules/{n}": {"version": v, "integrity": f"sha512-{n}-{v}", "resolved": "x"} for n, v in pkgs.items()}}})


def test_lockfile_change_takes_the_worst_verdict(tmp_path):
    svc, calls = make(tmp_path, {"a@1.0.0": "CLEAN", "a@2.0.0": "CLEAN", "b@1.0.0": "HIGH"})
    r = svc.check_lockfile(lock(a="1.0.0"), lock(a="2.0.0", b="1.0.0"))
    assert sorted(calls) == ["a@1.0.0", "a@2.0.0", "b@1.0.0"]   # the old version runs too, to compare
    assert (r["changed"], r["worst_verdict"], r["advice"]) == (2, "HIGH", "block")
    assert {p["package"]: p["previous_version"] for p in r["packages"]} == {"a": "1.0.0", "b": None}


def test_lockfile_scan_budget_leaves_rest_unknown_and_advises_review(tmp_path):
    svc, calls = make(tmp_path, {"a@1.0.0": "CLEAN", "b@1.0.0": "CLEAN"})
    r = svc.check_lockfile(None, lock(a="1.0.0", b="1.0.0"), max_scans=1)
    assert len(calls) == 1 and r["unscanned"] == 1 and r["advice"] == "review"


def test_bad_lockfile_is_an_input_error(tmp_path):
    svc, _ = make(tmp_path, {})
    with pytest.raises(InputError):
        svc.check_lockfile(None, "not json")


def test_report_ids_cannot_reach_other_paths(tmp_path):
    svc, _ = make(tmp_path, {})
    for bad in ("../../etc/passwd", "rh-20261104-120000-abcdef/../../x", ""):
        with pytest.raises(InputError):
            svc.report(bad)


def test_compare_raises_on_what_the_new_version_added(tmp_path):
    made = {}

    def scanner(name, version, cfg, integrity):
        r = report(name, version, "CLEAN", integrity)
        if version == "2.0.0":
            r.evidence = {"connects": ["x.attacker.dev"], "bait_reads": [], "execs": [], "writes": []}
            r.manifest = {"scripts": {"postinstall": "node s.js"}, "dependencies": []}
        made[version] = r
        return r
    svc = Service(Cache(str(tmp_path / "c.sqlite3")), ScanConfig(scans_dir=str(tmp_path / "scans")),
                  scanner=scanner, resolve=lambda n, v, r: f"sha512-{n}-{v}")
    out = svc.compare("p", "2.0.0", "1.0.0")
    assert out["version_alone"] == "CLEAN" and out["verdict"] == "HIGH" and out["advice"] == "block"
    assert {c["kind"] for c in out["changes"]} == {"domain", "install_script"} and out["previous_version"] == "1.0.0"


def test_lockfile_comparison_failure_keeps_the_verdict(tmp_path):
    svc, _ = make(tmp_path, {"a@2.0.0": "CLEAN"})     # a@1.0.0 cannot be scanned
    r = svc.check_lockfile(lock(a="1.0.0"), lock(a="2.0.0"))
    assert r["packages"][0]["verdict"] == "CLEAN" and "could not compare" in r["packages"][0]["changes_note"]


def aged(tmp_path, verdict, calls):
    now = [1000.0]

    def scanner(name, version, cfg, integrity):
        calls.append(name)
        return report(name, version, verdict, integrity)

    cache = Cache(str(tmp_path / "aged.sqlite3"), max_age_s=100.0, clock=lambda: now[0])
    svc = Service(cache, ScanConfig(scans_dir=str(tmp_path / "scans")), scanner=scanner, resolve=lambda n, v, r: f"sha512-{n}-{v}")
    return svc, now


@pytest.mark.parametrize("verdict", ["CLEAN", "REVIEW"])
def test_expired_evidence_runs_again_before_anything_gets_through(tmp_path, verdict):
    calls = []
    svc, now = aged(tmp_path, verdict, calls)
    svc.check("a", "1.0.0")
    now[0] += 100.0
    assert svc.check("a", "1.0.0")["cached"] is True and calls == ["a"]
    now[0] += 1.0
    assert svc.check("a", "1.0.0")["cached"] is False and calls == ["a", "a"]
    assert svc.check("a", "1.0.0")["cached"] is True and calls == ["a", "a"]


def test_expired_evidence_is_never_served_by_a_lookup(tmp_path):
    calls = []
    svc, now = aged(tmp_path, "CLEAN", calls)
    svc.check("a", "1.0.0")
    now[0] += 101.0
    out = svc.check("a", "1.0.0", scan_if_missing=False)
    assert out["verdict"] is None and out["advice"] == "unknown" and "expired" in out["note"] and calls == ["a"]


@pytest.mark.parametrize("verdict", ["HIGH", "CRITICAL"])
def test_a_block_does_not_expire(tmp_path, verdict):
    calls = []
    svc, now = aged(tmp_path, verdict, calls)
    svc.check("a", "1.0.0")
    now[0] += 10 ** 9
    out = svc.check("a", "1.0.0", scan_if_missing=False)
    assert out["verdict"] == verdict and out["advice"] == "block" and calls == ["a"]


def test_a_rescan_that_cannot_run_gives_no_verdict(tmp_path):
    now = [1000.0]
    runs = []

    def scanner(name, version, cfg, integrity):
        runs.append(name)
        if len(runs) > 1:
            raise ScanError("npm no longer serves it")
        return report(name, version, "CLEAN", integrity)

    svc = Service(Cache(str(tmp_path / "gone.sqlite3"), max_age_s=100.0, clock=lambda: now[0]),
                  ScanConfig(scans_dir=str(tmp_path / "scans")), scanner=scanner, resolve=lambda n, v, r: f"sha512-{n}-{v}")
    svc.check("a", "1.0.0")
    now[0] += 101.0
    with pytest.raises(ScanError):
        svc.check("a", "1.0.0")

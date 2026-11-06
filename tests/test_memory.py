from redhanded.memory import AttackMemory, as_item, report_traits, traits

STEALER = {"package": "evil", "version": "1.0.0", "verdict": "CRITICAL", "reasons": ["CRITICAL: x", "HIGH: spawned curl"],
           "evidence": {"bait_reads": ["/home/dev/.aws/credentials"], "token_uses": ["GitHub"], "exfil_matches": ["aws_access_key_id"], "connects": ["api.github.com", "sts.us-east-1.amazonaws.com"]}}
KNOWN = {"package": "@ctrl/tinycolor", "version": "4.1.1", "incident": "Shai-Hulud worm", "date": "2025-09-15"}


def memory(results, calls=None):
    def call(method, url, key, body, timeout):
        if calls is not None:
            calls.append((method, url, body))
        return {"results": [{"content": c} for c in results]}
    return AttackMemory("k", call=call)


def test_traits_ignore_what_changes_between_scans():
    a = traits(["HIGH: spawned curl"], [], [], [], ["x1.oastify.com"])
    b = traits(["HIGH: spawned curl"], [], [], [], ["y2.oastify.com"])
    assert a == b == {"spawned curl", "called collector oastify.com"}


def test_a_real_overlap_is_named():
    item = as_item({**KNOWN, "traits": report_traits(STEALER)})
    calls = []
    out = memory([item], calls).closest(STEALER)
    assert out["package"] == "@ctrl/tinycolor" and out["overlap"] == 1.0
    assert calls[0][1].endswith("/vector_store/rh_attacks/search")


def test_search_results_that_do_not_really_overlap_are_dropped():
    item = as_item({**KNOWN, "traits": {"wrote shell profile .bashrc", "modified the toolchain", "ran inline code", "called collector oastify.com"}})
    assert memory([item]).closest(STEALER) is None


def test_a_package_never_matches_itself():
    item = as_item({**KNOWN, "package": "evil", "traits": report_traits(STEALER)})
    assert memory([item]).closest(STEALER) is None


def test_too_little_behaviour_is_not_compared():
    assert memory([]).closest({"package": "x", "reasons": ["HIGH: spawned curl"], "evidence": {}}) is None


def test_failures_mean_no_match_and_never_raise():
    def boom(*a):
        raise TimeoutError
    assert AttackMemory("k", call=boom).closest(STEALER) is None
    assert memory(["garbage", "x\\nknown: {not json"]).closest(STEALER) is None


def test_lockfile_budget_goes_to_install_scripts_first(tmp_path):
    import json
    from redhanded.runner import Report, ScanConfig
    from redhanded.service import Cache, Service
    seen = []

    def scanner(name, version, cfg, integrity):
        seen.append(name)
        return Report(scan_id="rh-20261106-000000-000001", package=name, version=version, integrity=integrity, verdict="CLEAN", reasons=[], container_aware=False, seconds=1.0)

    svc = Service(Cache(str(tmp_path / "c.sqlite3")), ScanConfig(scans_dir=str(tmp_path)), scanner=scanner, resolve=lambda n, v, r: f"sha512-{n}")
    pkgs = {"": {"name": "a"}, "node_modules/a": {"version": "1.0.0", "integrity": "sha512-a"}, "node_modules/b": {"version": "1.0.0", "integrity": "sha512-b", "hasInstallScript": True},
            "node_modules/x/node_modules/c": {"version": "1.0.0", "integrity": "sha512-c"}}
    out = svc.check_lockfile(None, json.dumps({"lockfileVersion": 3, "packages": pkgs}), max_scans=2)
    assert seen == ["b", "a"] and out["unscanned"] == 1 and out["advice"] == "review"

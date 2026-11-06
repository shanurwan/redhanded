from redhanded.microvm import contacted, parse_console
from redhanded.runner import ScanConfig
from redhanded.sinkhole import Record
from redhanded.verdict import Evidence, Verdict, combine_microvm, decide


def test_console_report_is_parsed():
    text = "boot noise\r\nRH-WRITE /home/dev/.bashrc\r\nRH-READ /home/dev/.npmrc\r\nRH-REPORT-END\r\n"
    assert parse_console(text) == (["/home/dev/.bashrc"], ["/home/dev/.npmrc"], True)


def test_a_guest_that_stops_reporting_is_noticed():
    assert parse_console("RH-WRITE /x\n")[2] is False


def test_destinations_come_from_what_reached_the_sinkhole():
    records = [Record("dns", 1.0, "g", "c2.rh-zoo.invalid", "A"), Record("http", 1.0, "g", "c2.rh-zoo.invalid", "GET /"),
               Record("raw", 1.0, "g", "", "4444")]
    assert contacted(records) == ["c2.rh-zoo.invalid", "port 4444"]


def evaded():
    sandbox = Evidence(stats=["/proc/1/cgroup"])
    return sandbox, decide(sandbox)


def test_doing_in_the_microvm_what_it_hid_from_the_sandbox_is_high():
    sandbox, first = evaded()
    assert first.verdict == Verdict.REVIEW and first.container_aware
    microvm = Evidence(connects=["c2.rh-zoo.invalid"])
    out = combine_microvm(first, sandbox, decide(microvm), microvm)
    assert out.verdict == Verdict.HIGH
    assert any("hid this from the sandbox: c2.rh-zoo.invalid" in r for r in out.reasons)


def test_reading_bait_only_in_the_microvm_counts_as_hiding():
    sandbox, first = evaded()
    microvm = Evidence(bait_reads=["/home/dev/.npmrc"])
    assert combine_microvm(first, sandbox, decide(microvm), microvm).verdict == Verdict.HIGH


def test_same_behaviour_in_both_stays_at_review():
    sandbox, first = evaded()
    microvm = Evidence()
    out = combine_microvm(first, sandbox, decide(microvm), microvm)
    assert out.verdict == Verdict.REVIEW


def test_the_microvm_can_never_lower_a_verdict():
    sandbox = Evidence(exfil_matches=["npm_token"], stats=["/.dockerenv"])
    first = decide(sandbox)
    microvm = Evidence()
    assert combine_microvm(first, sandbox, decide(microvm), microvm).verdict == Verdict.CRITICAL


def test_an_incomplete_microvm_run_does_not_clear_a_package():
    sandbox, first = evaded()
    microvm = Evidence(incomplete=["the microVM guest did not finish its report"])
    out = combine_microvm(first, sandbox, decide(microvm), microvm)
    assert out.verdict == Verdict.REVIEW and any("did not finish" in r for r in out.reasons)


def test_microvm_tier_is_off_without_its_files(monkeypatch):
    for k in ("RH_FC_BIN", "RH_FC_KERNEL", "RH_FC_ROOTFS"):
        monkeypatch.delenv(k, raising=False)
    assert ScanConfig().microvm_ready() is False

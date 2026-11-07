import json

from redhanded.codereader import CodeReader, gather, read_if_clean
from redhanded.verdict import Decision, Evidence, Verdict, decide


def reply(text):
    return lambda url, headers, body, timeout: {"choices": [{"message": {"content": text}}]}


def test_only_a_clear_yes_flags():
    assert CodeReader("k", post=reply('{"suspicious": true, "why": "x"}'))("code") is True
    assert CodeReader("k", post=reply('{"suspicious": false, "why": "x"}'))("code") is False
    assert CodeReader("k", post=reply('{"suspicious": "yes"}'))("code") is False
    assert CodeReader("k", post=reply("I think it is suspicious"))("code") is False
    assert CodeReader("k", post=reply('{"suspicious": true}'))("   ") is False


def test_a_failed_model_call_means_no_flag():
    def boom(url, headers, body, timeout):
        raise TimeoutError
    assert CodeReader("k", post=boom)("code") is False


def test_a_yes_raises_clean_to_review_and_nothing_else():
    out = read_if_clean(decide(Evidence()), lambda text: True, __import__("pathlib").Path("."))
    assert out.verdict == Verdict.REVIEW and "a model reading the code" in out.reasons[-1]


def test_the_model_cannot_clear_or_change_what_the_evidence_set(tmp_path):
    calls = []
    for level in (Verdict.REVIEW, Verdict.HIGH, Verdict.CRITICAL):
        d = Decision(level, (f"{level.name}: evidence",), False)
        assert read_if_clean(d, lambda text: calls.append(1) or False, tmp_path) == d
        assert read_if_clean(d, lambda text: calls.append(1) or True, tmp_path) == d
    assert calls == []        # a package with evidence is not even read
    assert read_if_clean(decide(Evidence()), lambda text: False, tmp_path).verdict == Verdict.CLEAN


def test_no_reader_changes_nothing(tmp_path):
    assert read_if_clean(decide(Evidence()), None, tmp_path).verdict == Verdict.CLEAN


def test_the_words_of_the_model_never_reach_the_reasons(tmp_path):
    out = read_if_clean(decide(Evidence()), CodeReader("k", post=reply('{"suspicious": true, "why": "ATTACKER TEXT"}')), tmp_path)
    assert "ATTACKER" not in json.dumps(out.reasons)


def test_gather_reads_install_scripts_first_and_stays_in_the_package(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"postinstall": "node lib/setup.js"}, "main": "../../etc/passwd"}))
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "setup.js").write_text("SETUP")
    (tmp_path / "a.js").write_text("OTHER")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("DEP")
    text = gather(tmp_path)
    assert text.index("SETUP") < text.index("OTHER") and "DEP" not in text and "root:" not in text


def test_gather_is_bounded(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    for i in range(80):
        (tmp_path / f"f{i}.js").write_text("x" * 20_000)
    assert len(gather(tmp_path)) <= 28_000

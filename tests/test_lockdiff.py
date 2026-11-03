import pytest

from redhanded.lockdiff import LockfileError, diff


def lock(packages, version=3):
    return {"name": "demo", "lockfileVersion": version, "packages": {"": {"name": "demo"}, **packages}}


def pkg(version, integrity="sha512-aaa", install=False):
    entry = {"version": version, "resolved": f"https://registry.npmjs.org/x/-/x-{version}.tgz", "integrity": integrity}
    if install:
        entry["hasInstallScript"] = True
    return entry


def test_version_bump_and_new_transitive():
    old = lock({"node_modules/axios": pkg("1.14.0")})
    new = lock({
        "node_modules/axios": pkg("1.14.1", "sha512-bbb"),
        "node_modules/plain-crypto-js": pkg("4.2.1", "sha512-ccc", install=True),
    })
    changes = {c.name: c for c in diff(old, new)}
    assert changes["axios"].old_version == "1.14.0" and changes["axios"].new_version == "1.14.1"
    assert changes["plain-crypto-js"].old_version is None
    assert changes["plain-crypto-js"].has_install_script


def test_unchanged_packages_are_skipped():
    same = lock({"node_modules/lodash": pkg("4.17.21")})
    assert diff(same, same) == []


def test_same_version_new_integrity_is_a_change():
    old = lock({"node_modules/left-pad": pkg("1.3.0", "sha512-old")})
    new = lock({"node_modules/left-pad": pkg("1.3.0", "sha512-new")})
    assert [c.name for c in diff(old, new)] == ["left-pad"]


def test_nested_and_scoped_names():
    new = lock({
        "node_modules/a/node_modules/@scope/b": pkg("2.0.0"),
        "node_modules/linked": {"resolved": "../linked", "link": True},
    })
    assert [c.spec for c in diff(None, new)] == ["@scope/b@2.0.0"]


def test_old_lockfile_format_rejected():
    with pytest.raises(LockfileError):
        diff(None, {"lockfileVersion": 1, "dependencies": {}})

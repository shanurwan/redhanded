import os

import pytest

from redhanded.honeytokens import HoneytokenSet


def test_plant_writes_every_bait_file(tmp_path):
    t = HoneytokenSet.generate("s1")
    written = t.plant(tmp_path)
    assert len(written) == len(t.files())
    creds = (tmp_path / ".aws/credentials").read_text()
    assert t.aws_access_key_id in creds and t.aws_secret_access_key in creds
    assert t.ssh_key_marker not in (tmp_path / ".ssh/id_ed25519").read_text()  # marker is inside base64


def test_plant_refuses_to_overwrite(tmp_path):
    t = HoneytokenSet.generate("s1")
    t.plant(tmp_path)
    with pytest.raises(FileExistsError):
        t.plant(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_plant_refuses_symlinked_directory(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    (home / ".aws").symlink_to(outside)
    with pytest.raises(RuntimeError):
        HoneytokenSet.generate("s1").plant(home)


def test_token_formats():
    t = HoneytokenSet.generate("s1")
    assert t.aws_access_key_id.startswith("AKIA") and len(t.aws_access_key_id) == 20
    assert t.github_token.startswith("ghp_") and len(t.github_token) == 40
    assert t.npm_token.startswith("npm_")

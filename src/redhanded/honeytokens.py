"""Per-scan honeytokens: fake credentials planted where stealers look.

Every scan gets fresh random values, so finding one of them in outbound
traffic is proof the package took it, not a coincidence.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import string
from dataclasses import dataclass, field
from pathlib import Path

_UPPER_ALNUM = string.ascii_uppercase + string.digits
_ALNUM = string.ascii_letters + string.digits


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


@dataclass(frozen=True)
class HoneytokenSet:
    scan_id: str
    aws_access_key_id: str
    aws_secret_access_key: str
    npm_token: str
    github_token: str
    ssh_key_marker: str
    wallet_private_key: str
    metadata_access_key_id: str
    metadata_secret: str
    extra: dict[str, str] = field(default_factory=dict)

    @classmethod
    def generate(cls, scan_id: str) -> "HoneytokenSet":
        return cls(
            scan_id=scan_id,
            aws_access_key_id="AKIA" + _rand(_UPPER_ALNUM, 16),
            aws_secret_access_key=_rand(_ALNUM + "/+", 40),
            npm_token="npm_" + _rand(_ALNUM, 36),
            github_token="ghp_" + _rand(_ALNUM, 36),
            ssh_key_marker=_rand(_ALNUM, 32),
            wallet_private_key=secrets.token_hex(32),
            metadata_access_key_id="ASIA" + _rand(_UPPER_ALNUM, 16),
            metadata_secret=_rand(_ALNUM + "/+", 40),
        )

    def values(self) -> dict[str, str]:
        """Name -> secret value, for the matcher."""
        out = {
            "aws_access_key_id": self.aws_access_key_id,
            "aws_secret_access_key": self.aws_secret_access_key,
            "npm_token": self.npm_token,
            "github_token": self.github_token,
            "ssh_private_key": self.ssh_key_marker,
            "wallet_private_key": self.wallet_private_key,
            "metadata_access_key_id": self.metadata_access_key_id,
            "metadata_secret": self.metadata_secret,
        }
        out.update(self.extra)
        return out

    def env(self) -> dict[str, str]:
        """Environment variables injected into the sandbox."""
        return {
            "AWS_ACCESS_KEY_ID": self.aws_access_key_id,
            "AWS_SECRET_ACCESS_KEY": self.aws_secret_access_key,
            "NPM_TOKEN": self.npm_token,
            "GITHUB_TOKEN": self.github_token,
        }

    def metadata_credentials(self) -> dict[str, str]:
        """Body served by the sinkhole for the cloud metadata credential path."""
        return {
            "Code": "Success",
            "Type": "AWS-HMAC",
            "AccessKeyId": self.metadata_access_key_id,
            "SecretAccessKey": self.metadata_secret,
            "Token": base64.b64encode(self.metadata_secret.encode()).decode(),
            "Expiration": "2099-01-01T00:00:00Z",
        }

    def _ssh_key(self) -> str:
        body = base64.b64encode(
            b"openssh-key-v1\x00" + self.ssh_key_marker.encode() + secrets.token_bytes(48)
        ).decode()
        lines = [body[i : i + 70] for i in range(0, len(body), 70)]
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END OPENSSH PRIVATE KEY-----\n"

    def files(self) -> dict[str, str]:
        """Relative path under the fake home -> file content."""
        return {
            ".aws/credentials": (
                "[default]\n"
                f"aws_access_key_id = {self.aws_access_key_id}\n"
                f"aws_secret_access_key = {self.aws_secret_access_key}\n"
            ),
            ".npmrc": f"//registry.npmjs.org/:_authToken={self.npm_token}\n",
            ".ssh/id_ed25519": self._ssh_key(),
            ".config/gh/hosts.yml": (
                "github.com:\n"
                f"    oauth_token: {self.github_token}\n"
                "    git_protocol: https\n"
            ),
            ".env": (
                f"AWS_ACCESS_KEY_ID={self.aws_access_key_id}\n"
                f"AWS_SECRET_ACCESS_KEY={self.aws_secret_access_key}\n"
                f"GITHUB_TOKEN={self.github_token}\n"
            ),
            ".ethereum/keystore/wallet.json": json.dumps(
                {"address": secrets.token_hex(20), "private_key": self.wallet_private_key}
            ),
        }

    def plant(self, home: Path) -> list[Path]:
        """Write the bait files under `home`. Refuses to follow symlinks or overwrite."""
        written = []
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        for rel, content in self.files().items():
            path = home / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.parent.resolve() != (home.resolve() / Path(rel).parent):
                raise RuntimeError(f"refusing to plant through a symlinked directory: {rel}")
            fd = os.open(path, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf8", newline="\n") as fh:
                fh.write(content)
            written.append(path)
        return written

    def bait_paths(self, home: str = "/home/dev") -> set[str]:
        return {f"{home}/{rel}" for rel in self.files()}

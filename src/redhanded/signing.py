"""Signed verdicts: a statement anyone can check offline with the public key.

The statement names the exact bytes (the sha512 integrity), the verdict, the rules
that set it and when. It is signed as bytes, so checking it needs no JSON rules:
openssl or any Ed25519 library verifies `payload` against `signature`.

The key is made on first start and kept beside the cache. A signature proves which
service said it and that nothing was changed since. It does not make a verdict
truer than the evidence behind it, and a CLEAN statement is only current for as
long as the cache keeps CLEAN evidence (24 hours by default).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

TYPE = "redhanded.verdict/v1"
FIELDS = ("package", "version", "integrity", "verdict", "rules", "scan_id")
# A raw 32-byte Ed25519 key behind this prefix is the SubjectPublicKeyInfo openssl reads.
_SPKI = bytes.fromhex("302a300506032b6570032100")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def key_id(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()[:16]


def public_pem(raw: bytes) -> str:
    body = base64.encodebytes(_SPKI + raw).decode().replace("\n", "")
    return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n"


class Signer:
    def __init__(self, key: Ed25519PrivateKey, clock=time.time):
        self._key, self._clock = key, clock
        self.raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = key_id(self.raw)

    @classmethod
    def at(cls, path: str | Path, clock=time.time) -> "Signer":
        """Load the key at `path`, or make one there readable only by this user."""
        path = Path(path)
        if path.is_file():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError(f"{path} is not an Ed25519 key")
            return cls(key, clock)
        key = Ed25519PrivateKey.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return cls(key, clock)

    def public(self) -> dict:
        return {"alg": "ed25519", "key_id": self.key_id, "key": _b64(self.raw), "pem": public_pem(self.raw), "type": TYPE}

    def sign(self, answer: dict) -> dict | None:
        """A signature for one verdict answer, or None when it has no verdict on known bytes."""
        if not answer.get("verdict") or not str(answer.get("integrity") or "").startswith("sha"):
            return None
        statement = {"type": TYPE, **{k: answer.get(k) for k in FIELDS},
                     "signed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._clock())), "key_id": self.key_id}
        payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
        return {"statement": statement, "payload": _b64(payload), "signature": _b64(self._key.sign(payload)), "key_id": self.key_id}


def verify(public_key_b64: str, signed: dict, answer: dict | None = None) -> dict:
    """The signed statement, if the signature holds and it says what `answer` says. Raises ValueError otherwise."""
    try:
        payload, sig = base64.b64decode(signed["payload"]), base64.b64decode(signed["signature"])
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64)).verify(sig, payload)
    except (InvalidSignature, KeyError, ValueError, TypeError) as e:
        raise ValueError("signature does not match") from e
    statement = json.loads(payload)
    if statement.get("type") != TYPE:
        raise ValueError("not a RedHanded verdict statement")
    if answer is not None:
        wrong = [k for k in FIELDS if k in answer and answer[k] != statement.get(k)]
        if wrong:
            raise ValueError("the answer differs from what was signed: " + ", ".join(wrong))
    return statement

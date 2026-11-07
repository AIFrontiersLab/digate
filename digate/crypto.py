"""Ed25519 signing helpers for digest-bound verdicts."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from nacl import encoding, signing

from digate.errors import KeyError_


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def payload_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private_key_seed, public_key_bytes)."""
    key = signing.SigningKey.generate()
    return bytes(key), bytes(key.verify_key)


def save_keypair(keys_dir: Path, signer_id: str) -> Path:
    keys_dir.mkdir(parents=True, exist_ok=True)
    seed, pub = generate_keypair()
    priv_path = keys_dir / f"{signer_id}.priv"
    pub_path = keys_dir / f"{signer_id}.pub"
    priv_path.write_bytes(seed)
    pub_path.write_bytes(pub)
    priv_path.chmod(0o600)
    return priv_path


def load_signing_key(keys_dir: Path, signer_id: str) -> signing.SigningKey:
    path = keys_dir / f"{signer_id}.priv"
    if not path.exists():
        raise KeyError_(f"missing signing key for {signer_id}")
    return signing.SigningKey(path.read_bytes())


def load_verify_key(keys_dir: Path, signer_id: str) -> signing.VerifyKey:
    path = keys_dir / f"{signer_id}.pub"
    if not path.exists():
        raise KeyError_(f"missing verify key for {signer_id}")
    return signing.VerifyKey(path.read_bytes())


def sign_bytes(keys_dir: Path, signer_id: str, message: bytes) -> str:
    key = load_signing_key(keys_dir, signer_id)
    signed = key.sign(message)
    return base64.b64encode(signed.signature).decode("ascii")


def verify_signature(keys_dir: Path, signer_id: str, message: bytes, signature_b64: str) -> bool:
    try:
        verify_key = load_verify_key(keys_dir, signer_id)
        signature = base64.b64decode(signature_b64.encode("ascii"))
        verify_key.verify(message, signature)
        return True
    except Exception:
        return False


def fingerprint(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def encode_public_key(public_key: bytes) -> str:
    return encoding.Base64Encoder.encode(public_key).decode("ascii")

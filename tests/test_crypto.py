from __future__ import annotations

from pathlib import Path

from digate.crypto import (
    canonical_json,
    payload_hash,
    save_keypair,
    sign_bytes,
    verify_signature,
)


def test_sign_and_verify_roundtrip(tmp_path: Path) -> None:
    save_keypair(tmp_path, "scanner")
    message = canonical_json({"digest": "abc", "outcome": "pass"})
    signature = sign_bytes(tmp_path, "scanner", message)
    assert verify_signature(tmp_path, "scanner", message, signature)
    assert not verify_signature(tmp_path, "scanner", b"tampered", signature)


def test_payload_hash_stable() -> None:
    a = payload_hash({"b": 2, "a": 1})
    b = payload_hash({"a": 1, "b": 2})
    assert a == b

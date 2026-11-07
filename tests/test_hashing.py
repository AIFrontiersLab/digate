from __future__ import annotations

from pathlib import Path

from digate.hashing import format_digest, sha256_file, sha256_text


def test_sha256_text_known_vector() -> None:
    assert sha256_text("abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_sha256_file(tmp_path: Path) -> None:
    path = tmp_path / "blob.bin"
    path.write_bytes(b"abc")
    assert sha256_file(path) == sha256_text("abc")
    assert format_digest(sha256_text("abc")).startswith("sha256:")

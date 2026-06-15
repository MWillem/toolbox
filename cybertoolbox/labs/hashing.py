from __future__ import annotations

import hashlib
from pathlib import Path

from .hash_advanced import hash_generate


ALGORITHMS = (
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "blake2b",
    "sha3_256",
    "sha3_512",
)


def hash_text(text: str, algorithm: str = "sha256") -> str:
    return hash_generate(text, algorithm)


def hash_file(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()

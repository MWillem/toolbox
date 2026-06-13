from __future__ import annotations

import hashlib
from pathlib import Path


ALGORITHMS = ("sha256", "sha512", "blake2b")


def hash_text(text: str, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    digest.update(text.encode("utf-8"))
    return digest.hexdigest()


def hash_file(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()

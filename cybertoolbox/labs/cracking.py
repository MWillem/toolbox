from __future__ import annotations

import hashlib
import time


MAX_CANDIDATES = 100_000


def crack_demo_hash(
    target_hash: str,
    candidates: list[str],
    algorithm: str = "sha256",
) -> dict[str, object]:
    """Try a bounded local word list against a hash created for the lab."""
    normalized = target_hash.strip().lower()
    start = time.perf_counter()
    tested = 0
    found = None
    for candidate in candidates[:MAX_CANDIDATES]:
        tested += 1
        digest = hashlib.new(algorithm, candidate.rstrip("\r\n").encode("utf-8")).hexdigest()
        if digest == normalized:
            found = candidate.rstrip("\r\n")
            break
    return {
        "found": found,
        "tested": tested,
        "elapsed": round(time.perf_counter() - start, 4),
        "algorithm": algorithm,
    }

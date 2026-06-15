from __future__ import annotations

import hashlib
import time


MAX_CANDIDATES = 100_000
MAX_WIFI_CANDIDATES = 10_000


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


def derive_wpa2_pmk(ssid: str, password: str) -> str:
    if not 1 <= len(ssid.encode("utf-8")) <= 32:
        raise ValueError("Le SSID doit contenir entre 1 et 32 octets.")
    if not 8 <= len(password) <= 63:
        raise ValueError("Un mot de passe WPA2 de démonstration doit contenir 8 à 63 caractères.")
    return hashlib.pbkdf2_hmac(
        "sha1",
        password.encode("utf-8"),
        ssid.encode("utf-8"),
        4096,
        32,
    ).hex()


def crack_wpa2_demo(
    ssid: str,
    target_pmk: str,
    candidates: list[str],
) -> dict[str, object]:
    """Bounded offline WPA2 key-derivation demonstration for an authorized lab."""
    start = time.perf_counter()
    tested = 0
    found = None
    for candidate in candidates[:MAX_WIFI_CANDIDATES]:
        value = candidate.rstrip("\r\n")
        if not 8 <= len(value) <= 63:
            continue
        tested += 1
        if derive_wpa2_pmk(ssid, value) == target_pmk.lower():
            found = value
            break
    return {
        "found": found,
        "tested": tested,
        "elapsed": round(time.perf_counter() - start, 4),
        "ssid": ssid,
        "method": "PBKDF2-HMAC-SHA1, 4096 itérations",
    }

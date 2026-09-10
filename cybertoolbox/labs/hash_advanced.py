from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
import re
import struct
import time


SUPPORTED_ALGORITHMS = (
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "blake2b",
    "sha3_256",
    "sha3_512",
    "ntlm",
)


def hash_generate(text: str, algorithm: str = "sha256") -> str:
    """Génère le condensat d'un texte avec l'algorithme demandé."""
    normalized = algorithm.lower()
    if normalized == "ntlm":
        return hash_ntlm(text)
    if normalized not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Algorithme non supporté : {algorithm}")
    digest = hashlib.new(normalized)
    digest.update(text.encode("utf-8"))
    return digest.hexdigest()


def hash_file(path: str, algorithm: str = "sha256") -> str:
    """Calcule progressivement le hash d'un fichier sans le charger entièrement."""
    normalized = algorithm.lower()
    if normalized == "ntlm":
        raise ValueError("NTLM s'applique à un mot de passe, pas à un fichier.")
    if normalized not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Algorithme non supporté : {algorithm}")
    source = Path(path).expanduser()
    if not source.is_file():
        raise ValueError("Le fichier à hacher est introuvable.")
    digest = hashlib.new(normalized)
    with source.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_ntlm(password: str) -> str:
    """Calcule le hash NTLM historique d'un mot de passe encodé en UTF-16LE."""
    payload = password.encode("utf-16le")
    try:
        digest = hashlib.new("md4")
        digest.update(payload)
        return digest.hexdigest()
    except (ValueError, TypeError):
        return _md4(payload).hex()


def identify_hash(hash_string: str) -> list[dict[str, object]]:
    """Identifie les formats de hash probables par préfixe, longueur et alphabet."""
    value = hash_string.strip()
    matches: list[dict[str, object]] = []
    prefix_rules = (
        (r"^\$2[aby]\$(\d{2})\$", "bcrypt"),
        (r"^\$argon2(id|i|d)\$", "argon2"),
        (r"^\$6\$", "sha512crypt"),
        (r"^\$5\$", "sha256crypt"),
        (r"^\$1\$", "md5crypt"),
        (r"^\$P\$", "phpass"),
    )
    for pattern, name in prefix_rules:
        found = re.match(pattern, value)
        if found:
            item: dict[str, object] = {
                "algorithm": name,
                "confidence": "élevée",
                "reason": f"Préfixe caractéristique de {name}.",
            }
            if name == "bcrypt":
                item["cost"] = int(found.group(1))
            matches.append(item)
    if matches:
        return matches
    if not re.fullmatch(r"[0-9a-fA-F]+", value):
        return []
    length_rules = {
        32: (
            ("md5", "moyenne"),
            ("ntlm", "moyenne"),
        ),
        40: (("sha1", "élevée"),),
        56: (("sha224", "élevée"),),
        64: (
            ("sha256", "moyenne"),
            ("sha3_256", "moyenne"),
        ),
        96: (("sha384", "élevée"),),
        128: (
            ("sha512", "moyenne"),
            ("sha3_512", "moyenne"),
            ("blake2b", "moyenne"),
        ),
    }
    for algorithm, confidence in length_rules.get(len(value), ()):
        matches.append(
            {
                "algorithm": algorithm,
                "confidence": confidence,
                "reason": (
                    f"Chaîne hexadécimale de {len(value)} caractères. "
                    "La longueur seule ne prouve pas l'algorithme."
                ),
            }
        )
    return matches


def crack_hash(
    hash_string: str,
    wordlist_path: str,
    algorithm: str = "auto",
) -> dict[str, object]:
    """Teste hors ligne les candidats d'une wordlist contre un hash de laboratoire."""
    target = hash_string.strip().lower()
    algorithms = _cracking_algorithms(target, algorithm)
    source = Path(wordlist_path).expanduser()
    if not source.is_file():
        raise ValueError("La wordlist est introuvable.")
    tested = 0
    started = time.perf_counter()
    with source.open("r", encoding="utf-8", errors="replace") as file:
        for line in file:
            candidate = line.rstrip("\r\n")
            if not candidate:
                continue
            tested += 1
            for current in algorithms:
                generated = hash_generate(candidate, current)
                if hmac.compare_digest(generated.lower(), target):
                    return {
                        "found": True,
                        "password": candidate,
                        "tested": tested,
                        "elapsed": round(time.perf_counter() - started, 4),
                        "algorithm": current,
                    }
    return {
        "found": False,
        "password": None,
        "tested": tested,
        "elapsed": round(time.perf_counter() - started, 4),
        "algorithm": algorithms[0] if len(algorithms) == 1 else algorithms,
    }


def generate_demo_hash(password: str, algorithm: str) -> str:
    """Crée un hash de démonstration pour le laboratoire hors ligne."""
    if not password:
        raise ValueError("Le mot de passe de démonstration ne peut pas être vide.")
    return hash_generate(password, algorithm)


def hash_security_lesson() -> str:
    """Explique le rôle du hash et les bonnes pratiques de stockage des secrets."""
    return (
        "Un hash est une empreinte à sens unique, pas un chiffrement. MD5, SHA-1 "
        "et NTLM sont trop rapides pour stocker des mots de passe : une attaque "
        "par dictionnaire peut tester beaucoup de candidats. Les applications "
        "doivent utiliser un sel unique et une fonction lente adaptée comme "
        "Argon2id, scrypt, bcrypt ou PBKDF2, avec un coût régulièrement réévalué."
    )


def _cracking_algorithms(target: str, algorithm: str) -> list[str]:
    normalized = algorithm.lower()
    if normalized != "auto":
        if normalized not in SUPPORTED_ALGORITHMS:
            raise ValueError(f"Algorithme non supporté : {algorithm}")
        return [normalized]
    identified = identify_hash(target)
    candidates = [
        str(item["algorithm"])
        for item in identified
        if item["algorithm"] in SUPPORTED_ALGORITHMS
    ]
    if not candidates:
        raise ValueError("Le type de hash n'a pas pu être identifié automatiquement.")
    return list(dict.fromkeys(candidates))


def _md4(message: bytes) -> bytes:
    """Implémentation minimale de MD4 pour la compatibilité NTLM."""
    original_length = len(message)
    data = bytearray(message)
    data.append(0x80)
    while len(data) % 64 != 56:
        data.append(0)
    data.extend(struct.pack("<Q", original_length * 8))
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    def left_rotate(value: int, count: int) -> int:
        value &= 0xFFFFFFFF
        return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF

    def f(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    def g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    for offset in range(0, len(data), 64):
        words = struct.unpack("<16I", data[offset:offset + 64])
        aa, bb, cc, dd = a, b, c, d
        for index in range(0, 16, 4):
            a = left_rotate(a + f(b, c, d) + words[index], 3)
            d = left_rotate(d + f(a, b, c) + words[index + 1], 7)
            c = left_rotate(c + f(d, a, b) + words[index + 2], 11)
            b = left_rotate(b + f(c, d, a) + words[index + 3], 19)
        for index in range(4):
            a = left_rotate(a + g(b, c, d) + words[index] + 0x5A827999, 3)
            d = left_rotate(d + g(a, b, c) + words[index + 4] + 0x5A827999, 5)
            c = left_rotate(c + g(d, a, b) + words[index + 8] + 0x5A827999, 9)
            b = left_rotate(b + g(c, d, a) + words[index + 12] + 0x5A827999, 13)
        for first, second, third, fourth in (
            (0, 8, 4, 12),
            (2, 10, 6, 14),
            (1, 9, 5, 13),
            (3, 11, 7, 15),
        ):
            a = left_rotate(a + h(b, c, d) + words[first] + 0x6ED9EBA1, 3)
            d = left_rotate(d + h(a, b, c) + words[second] + 0x6ED9EBA1, 9)
            c = left_rotate(c + h(d, a, b) + words[third] + 0x6ED9EBA1, 11)
            b = left_rotate(b + h(c, d, a) + words[fourth] + 0x6ED9EBA1, 15)
        a = (aa + a) & 0xFFFFFFFF
        b = (bb + b) & 0xFFFFFFFF
        c = (cc + c) & 0xFFFFFFFF
        d = (dd + d) & 0xFFFFFFFF
    return struct.pack("<4I", a, b, c, d)

from __future__ import annotations

import math
import re


COMMON_PATTERNS = ("password", "azerty", "qwerty", "1234", "admin", "letmein")


def analyze_password(password: str) -> dict[str, object]:
    pools = [
        (r"[a-z]", 26, "minuscules"),
        (r"[A-Z]", 26, "majuscules"),
        (r"\d", 10, "chiffres"),
        (r"[^A-Za-z0-9]", 33, "symboles"),
    ]
    pool_size = sum(size for pattern, size, _ in pools if re.search(pattern, password))
    entropy = len(password) * math.log2(pool_size) if pool_size else 0.0

    advice = []
    if len(password) < 14:
        advice.append("Utiliser au moins 14 caractères.")
    for pattern, _, label in pools:
        if not re.search(pattern, password):
            advice.append(f"Ajouter des {label}.")
    if any(pattern in password.lower() for pattern in COMMON_PATTERNS):
        advice.append("Éviter les mots et suites trop courants.")

    if entropy >= 80 and not advice:
        level = "fort"
    elif entropy >= 55:
        level = "moyen"
    else:
        level = "faible"

    return {
        "length": len(password),
        "entropy": round(entropy, 1),
        "level": level,
        "advice": advice or ["Bon équilibre. Utiliser un mot de passe unique et un gestionnaire."],
    }

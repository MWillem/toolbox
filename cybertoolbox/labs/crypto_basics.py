from __future__ import annotations

import base64
import binascii


def base64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def base64_decode(value: str) -> str:
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise ValueError("Valeur Base64 invalide ou non UTF-8.") from exc


def xor_encrypt(text: str, key: str) -> str:
    if not key:
        raise ValueError("La clé de démonstration ne peut pas être vide.")
    data = text.encode("utf-8")
    key_bytes = key.encode("utf-8")
    encrypted = bytes(value ^ key_bytes[index % len(key_bytes)] for index, value in enumerate(data))
    return base64.b64encode(encrypted).decode("ascii")


def xor_decrypt(value: str, key: str) -> str:
    if not key:
        raise ValueError("La clé de démonstration ne peut pas être vide.")
    try:
        data = base64.b64decode(value, validate=True)
        key_bytes = key.encode("utf-8")
        clear = bytes(item ^ key_bytes[index % len(key_bytes)] for index, item in enumerate(data))
        return clear.decode("utf-8")
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise ValueError("Donnée ou clé incorrecte.") from exc


def concepts_summary() -> str:
    return (
        "- Encodage : change la représentation, sans secret (ex. Base64).\n"
        "- Hachage : produit une empreinte non réversible pour l'intégrité.\n"
        "- Chiffrement : protège un contenu avec une clé et doit être réversible.\n"
        "- XOR du lab : illustre la réversibilité mais ne doit jamais protéger de vraies données."
    )

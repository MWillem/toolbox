from __future__ import annotations

import json
from pathlib import Path
import platform
import shutil
import subprocess
from typing import Any


def scan_nfc(timeout: int = 5) -> dict[str, Any]:
    """Détecte un tag NFC avec Termux:API ou libnfc selon la plateforme."""
    duration = max(1, min(int(timeout), 60))
    if shutil.which("termux-nfc-scan"):
        return _run_json_command(
            ["termux-nfc-scan"],
            duration,
            "Termux:API",
        )
    if shutil.which("nfc-poll"):
        result = _run_command(["nfc-poll"], duration)
        return {
            "supported": True,
            "available": result["success"],
            "engine": "libnfc nfc-poll",
            "raw": result["output"],
            "records": [],
            "explanation": (
                "Lecture brute fournie par libnfc. Le contenu dépend du lecteur, "
                "du pilote et du type de tag."
            ),
        }
    if shutil.which("nfc-list"):
        result = _run_command(["nfc-list"], duration)
        return {
            "supported": True,
            "available": result["success"],
            "engine": "libnfc nfc-list",
            "raw": result["output"],
            "records": [],
            "explanation": "Inventaire des lecteurs NFC disponibles.",
        }
    return {
        "supported": False,
        "available": False,
        "engine": "-",
        "raw": "",
        "records": [],
        "explanation": _unsupported_explanation(),
    }


def parse_ndef_record(raw_data: bytes) -> dict[str, Any]:
    """Analyse un enregistrement NDEF court de type texte, URI ou MIME."""
    if len(raw_data) < 3:
        raise ValueError("Donnée NDEF trop courte.")
    header = raw_data[0]
    short_record = bool(header & 0x10)
    has_identifier = bool(header & 0x08)
    type_name_format = header & 0x07
    type_length = raw_data[1]
    index = 2
    if short_record:
        payload_length = raw_data[index]
        index += 1
    else:
        if len(raw_data) < index + 4:
            raise ValueError("Longueur NDEF invalide.")
        payload_length = int.from_bytes(raw_data[index:index + 4], "big")
        index += 4
    identifier_length = raw_data[index] if has_identifier else 0
    if has_identifier:
        index += 1
    end = index + type_length + identifier_length + payload_length
    if end > len(raw_data):
        raise ValueError("Enregistrement NDEF tronqué.")
    record_type = raw_data[index:index + type_length]
    index += type_length
    identifier = raw_data[index:index + identifier_length]
    index += identifier_length
    payload = raw_data[index:index + payload_length]
    result: dict[str, Any] = {
        "tnf": type_name_format,
        "type": record_type.decode("ascii", errors="replace"),
        "identifier": identifier.hex(),
        "payload_hex": payload.hex(),
    }
    if type_name_format == 1 and record_type == b"T":
        result.update(_decode_text_payload(payload))
    elif type_name_format == 1 and record_type == b"U":
        result.update(_decode_uri_payload(payload))
    elif type_name_format == 2:
        result["kind"] = "mime"
        result["value"] = payload.decode("utf-8", errors="replace")
    else:
        text = payload.decode("utf-8", errors="replace")
        result["kind"] = _classify_text(text)
        result["value"] = text
    return result


def write_nfc_url(url: str) -> bool:
    """Écrit une URL sur un tag lorsque l'outil local le permet."""
    if not url.startswith(("http://", "https://")):
        raise ValueError("L'URL doit commencer par http:// ou https://.")
    return _write_nfc("url", url)


def write_nfc_text(text: str) -> bool:
    """Écrit un texte sur un tag NFC compatible."""
    if not text:
        raise ValueError("Le texte NFC ne peut pas être vide.")
    return _write_nfc("text", text)


def write_nfc_vcard(name: str, phone: str, email: str) -> bool:
    """Écrit une vCard simple sur un tag NFC compatible."""
    if not name.strip():
        raise ValueError("Le nom de la vCard ne peut pas être vide.")
    vcard = "\n".join(
        (
            "BEGIN:VCARD",
            "VERSION:3.0",
            f"FN:{name.strip()}",
            f"TEL:{phone.strip()}",
            f"EMAIL:{email.strip()}",
            "END:VCARD",
        )
    )
    return _write_nfc("text", vcard)


def clone_tag(uid: str, data: dict[str, Any], output_path: str) -> bool:
    """Sauvegarde la lecture d'un tag pour une démonstration et une analyse.

    Cette fonction ne programme pas un UID, n'émule pas un badge et ne permet
    pas de contourner un contrôle d'accès.
    """
    destination = Path(output_path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "uid": uid.strip(),
        "data": data,
        "educational_notice": (
            "Copie documentaire uniquement. Aucun UID n'est émulé ou écrit."
        ),
    }
    destination.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return True


def nfc_security_lesson() -> str:
    """Retourne une leçon sur les risques et protections liés au NFC."""
    return (
        "Le NFC est une technologie à très courte portée, mais la proximité ne "
        "remplace pas l'authentification. Un tag URL peut rediriger vers un site "
        "malveillant et certains badges anciens reposent sur des identifiants ou "
        "des secteurs clonables. Les paiements modernes ajoutent cryptographie, "
        "jetons et vérification du terminal. Pour se protéger : vérifier l'action "
        "avant validation, ne pas utiliser un UID comme unique secret, chiffrer "
        "les données sensibles et révoquer rapidement un badge perdu."
    )


def _write_nfc(kind: str, value: str) -> bool:
    candidates = (
        ["termux-nfc-write", kind, value],
        ["nfc-write", kind, value],
    )
    for command in candidates:
        if shutil.which(command[0]):
            return bool(_run_command(command, 30)["success"])
    return False


def _run_json_command(
    command: list[str],
    timeout: int,
    engine: str,
) -> dict[str, Any]:
    result = _run_command(command, timeout)
    try:
        payload = json.loads(result["output"]) if result["output"] else {}
    except json.JSONDecodeError:
        payload = {"raw": result["output"]}
    return {
        "supported": True,
        "available": result["success"],
        "engine": engine,
        "raw": result["output"],
        "records": payload if isinstance(payload, list) else [payload],
        "explanation": (
            "Le résultat provient de l'API NFC locale et dépend des permissions Android."
        ),
    }


def _run_command(command: list[str], timeout: int) -> dict[str, Any]:
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"success": False, "output": str(exc)}
    output = process.stdout.strip() or process.stderr.strip()
    return {"success": process.returncode == 0, "output": output}


def _decode_text_payload(payload: bytes) -> dict[str, str]:
    if not payload:
        return {"kind": "text", "language": "", "value": ""}
    status = payload[0]
    language_length = status & 0x3F
    encoding = "utf-16" if status & 0x80 else "utf-8"
    language = payload[1:1 + language_length].decode("ascii", errors="replace")
    value = payload[1 + language_length:].decode(encoding, errors="replace")
    return {"kind": "text", "language": language, "value": value}


def _decode_uri_payload(payload: bytes) -> dict[str, str]:
    prefixes = (
        "",
        "http://www.",
        "https://www.",
        "http://",
        "https://",
        "tel:",
        "mailto:",
        "ftp://anonymous:anonymous@",
        "ftp://ftp.",
        "ftps://",
        "sftp://",
        "smb://",
        "nfs://",
        "ftp://",
        "dav://",
        "news:",
        "telnet://",
        "imap:",
        "rtsp://",
        "urn:",
        "pop:",
        "sip:",
        "sips:",
        "tftp:",
        "btspp://",
        "btl2cap://",
        "btgoep://",
        "tcpobex://",
        "irdaobex://",
        "file://",
        "urn:epc:id:",
        "urn:epc:tag:",
        "urn:epc:pat:",
        "urn:epc:raw:",
        "urn:epc:",
        "urn:nfc:",
    )
    if not payload:
        return {"kind": "url", "value": ""}
    prefix = prefixes[payload[0]] if payload[0] < len(prefixes) else ""
    return {
        "kind": "url",
        "value": prefix + payload[1:].decode("utf-8", errors="replace"),
    }


def _classify_text(value: str) -> str:
    upper = value.upper()
    if value.startswith(("http://", "https://")):
        return "url"
    if upper.startswith("BEGIN:VCARD"):
        return "vcard"
    return "text"


def _unsupported_explanation() -> str:
    system = platform.system()
    if system in {"Windows", "Darwin"}:
        return (
            f"Non supporté automatiquement sur {system}. Utilisez un lecteur NFC "
            "compatible et son SDK, ou Termux:API/libnfc sur un système pris en charge."
        )
    return (
        "Non supporté : installez Termux:API avec `termux-nfc-scan` ou libnfc "
        "avec `nfc-poll`/`nfc-list`, puis vérifiez les permissions du lecteur."
    )

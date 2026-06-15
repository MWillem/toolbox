from __future__ import annotations

from pathlib import Path
from typing import Any


def generate_qr_text(text: str) -> str:
    """Génère un QR Code sous forme d'art ASCII lisible dans un terminal."""
    if not text:
        raise ValueError("Le contenu du QR Code ne peut pas être vide.")
    try:
        import qrcode
    except ImportError as exc:
        raise RuntimeError(
            "La génération QR nécessite `qrcode[pil]`. "
            "Installez les dépendances du projet."
        ) from exc
    qr = qrcode.QRCode(border=2)
    qr.add_data(text)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    return "\n".join(
        "".join("██" if cell else "  " for cell in row)
        for row in matrix
    )


def generate_qr_wifi(
    ssid: str,
    password: str,
    security: str = "WPA",
) -> str:
    """Génère un QR Wi-Fi standard sans tenter de rejoindre le réseau."""
    if not ssid.strip():
        raise ValueError("Le SSID ne peut pas être vide.")
    security_value = security.strip().upper() or "WPA"
    if security_value not in {"WPA", "WEP", "NOPASS"}:
        raise ValueError("La sécurité doit être WPA, WEP ou nopass.")
    data = (
        f"WIFI:T:{security_value};S:{_escape_wifi(ssid)};"
        f"P:{_escape_wifi(password)};;"
    )
    return generate_qr_text(data)


def generate_qr_vcard(name: str, phone: str, email: str) -> str:
    """Génère une vCard 3.0 encodée dans un QR Code ASCII."""
    if not name.strip():
        raise ValueError("Le nom de la vCard ne peut pas être vide.")
    data = "\n".join(
        (
            "BEGIN:VCARD",
            "VERSION:3.0",
            f"FN:{_escape_vcard(name)}",
            f"TEL:{_escape_vcard(phone)}",
            f"EMAIL:{_escape_vcard(email)}",
            "END:VCARD",
        )
    )
    return generate_qr_text(data)


def save_qr_png(data: str, path: str) -> None:
    """Sauvegarde un QR Code dans un fichier PNG avec la bibliothèque qrcode."""
    if not data:
        raise ValueError("Le contenu du QR Code ne peut pas être vide.")
    destination = Path(path).expanduser()
    if destination.suffix.lower() != ".png":
        destination = destination.with_suffix(".png")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        import qrcode
    except ImportError as exc:
        raise RuntimeError(
            "La sauvegarde PNG nécessite `qrcode[pil]`. "
            "Installez les dépendances du projet."
        ) from exc
    image = qrcode.make(data)
    image.save(destination)


def read_qr_from_file(path: str) -> dict[str, Any]:
    """Lit les QR Codes d'une image avec pyzbar ou OpenCV lorsqu'ils existent."""
    source = Path(path).expanduser()
    if not source.is_file():
        raise ValueError("Le fichier image est introuvable.")
    pyzbar_result = _read_with_pyzbar(source)
    if pyzbar_result is not None:
        return pyzbar_result
    opencv_result = _read_with_opencv(source)
    if opencv_result is not None:
        return opencv_result
    return {
        "available": False,
        "engine": "-",
        "items": [],
        "explanation": (
            "Lecture indisponible. Installez `pyzbar` avec la bibliothèque "
            "système zbar, ou OpenCV (`opencv-python`)."
        ),
    }


def read_qr_from_camera() -> dict[str, Any]:
    """Lit un QR depuis la webcam locale dans un mode de démonstration."""
    try:
        import cv2
    except ImportError:
        return {
            "available": False,
            "engine": "-",
            "items": [],
            "explanation": (
                "La lecture caméra nécessite OpenCV. Sur Termux et certains "
                "systèmes sans webcam, utilisez plutôt une image enregistrée."
            ),
        }
    camera = cv2.VideoCapture(0)
    if not camera.isOpened():
        return {
            "available": False,
            "engine": "OpenCV",
            "items": [],
            "explanation": "Aucune caméra accessible ou permission refusée.",
        }
    detector = cv2.QRCodeDetector()
    try:
        for _ in range(150):
            ok, frame = camera.read()
            if not ok:
                continue
            data, points, _ = detector.detectAndDecode(frame)
            if points is not None and data:
                return {
                    "available": True,
                    "engine": "OpenCV",
                    "items": [{"type": _classify_qr(data), "data": data}],
                    "explanation": "QR Code lu depuis la caméra locale.",
                }
    finally:
        camera.release()
    return {
        "available": True,
        "engine": "OpenCV",
        "items": [],
        "explanation": "Aucun QR Code détecté pendant la démonstration.",
    }


def decode_qr_wifi(qr_data: str) -> dict[str, str]:
    """Décode les champs principaux d'un QR Wi-Fi standard."""
    if not qr_data.upper().startswith("WIFI:"):
        raise ValueError("Cette donnée n'est pas un QR Wi-Fi.")
    fields = _split_wifi_fields(qr_data[5:])
    return {
        "ssid": fields.get("S", ""),
        "password": fields.get("P", ""),
        "type": fields.get("T", "nopass"),
        "hidden": fields.get("H", "false").lower(),
    }


def demonstrate_qr_phishing() -> str:
    """Explique les risques de phishing par QR Code sans créer de piège réel."""
    return (
        "Un QR Code masque sa destination jusqu'à sa lecture. Un attaquant peut "
        "remplacer un QR légitime par une URL ressemblante afin de demander des "
        "identifiants. Avant d'ouvrir : prévisualiser l'URL, vérifier le domaine "
        "et HTTPS, refuser les téléchargements inattendus et ne jamais saisir un "
        "secret après un scan non vérifié."
    )


def generate_demo_qr_payload(payload_type: str) -> str:
    """Génère un QR factice sûr pour apprendre à identifier un contenu suspect."""
    payloads = {
        "phishing": "https://example.invalid/demo-phishing",
        "download": "https://example.invalid/demo-download.txt",
        "wifi": "WIFI:T:WPA;S:DEMO-UNTRUSTED;P:not-a-real-password;;",
        "contact": "BEGIN:VCARD\nVERSION:3.0\nFN:DEMO INCONNU\nEND:VCARD",
    }
    key = payload_type.strip().lower()
    if key not in payloads:
        raise ValueError(
            "Type inconnu. Choisissez phishing, download, wifi ou contact."
        )
    return generate_qr_text(payloads[key])


def _read_with_pyzbar(path: Path) -> dict[str, Any] | None:
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode
    except (ImportError, OSError):
        return None
    items = [
        {
            "type": item.type,
            "data": item.data.decode("utf-8", errors="replace"),
        }
        for item in decode(Image.open(path))
    ]
    return {
        "available": True,
        "engine": "pyzbar",
        "items": items,
        "explanation": "Lecture locale de l'image, sans envoi vers Internet.",
    }


def _read_with_opencv(path: Path) -> dict[str, Any] | None:
    try:
        import cv2
    except ImportError:
        return None
    image = cv2.imread(str(path))
    if image is None:
        raise ValueError("L'image ne peut pas être décodée.")
    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(image)
    items = (
        [{"type": _classify_qr(data), "data": data}]
        if points is not None and data
        else []
    )
    return {
        "available": True,
        "engine": "OpenCV",
        "items": items,
        "explanation": "Lecture locale de l'image, sans envoi vers Internet.",
    }


def _classify_qr(data: str) -> str:
    upper = data.upper()
    if upper.startswith("WIFI:"):
        return "WIFI"
    if upper.startswith("BEGIN:VCARD"):
        return "VCARD"
    if data.startswith(("http://", "https://")):
        return "URL"
    return "TEXT"


def _escape_wifi(value: str) -> str:
    escaped = value.replace("\\", "\\\\")
    for character in (";", ",", ":", '"'):
        escaped = escaped.replace(character, f"\\{character}")
    return escaped


def _split_wifi_fields(value: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    current: list[str] = []
    escaped = False
    parts: list[str] = []
    for character in value:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ";":
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    if current:
        parts.append("".join(current))
    for part in parts:
        if ":" in part:
            key, item = part.split(":", 1)
            fields[key] = item
    return fields


def _escape_vcard(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace(";", "\\;")
        .replace(",", "\\,")
    )

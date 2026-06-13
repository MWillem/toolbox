from __future__ import annotations

from datetime import datetime
from pathlib import Path
import hashlib
import re


INDICATORS = {
    r"\b(?:curl|wget)\b": "Téléchargement de contenu distant",
    r"\b(?:nc|netcat|ncat)\b": "Utilisation de Netcat",
    r"\b(?:powershell|pwsh)\b": "Exécution PowerShell",
    r"\b(?:chmod|Start-Process)\b": "Modification ou lancement de programme",
    r"\b(?:eval|exec)\b": "Exécution dynamique de code",
    r"(?:/dev/tcp|TCPClient|socket\.)": "Primitive de connexion réseau",
}


def analyze_payload_file(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    text = data.decode("utf-8", errors="replace")
    findings = []
    for pattern, explanation in INDICATORS.items():
        if re.search(pattern, text, flags=re.IGNORECASE):
            findings.append(explanation)
    return {
        "name": path.name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "findings": findings,
    }


def create_harmless_payload(lab_dir: Path) -> Path:
    """Create a harmless artifact to demonstrate delivery without execution."""
    lab_dir.mkdir(parents=True, exist_ok=True)
    path = lab_dir / "payload_demo.txt"
    path.write_text(
        "CYBER TOOLBOX - PAYLOAD INOFFENSIF\n"
        f"Déposé le {datetime.now().isoformat(timespec='seconds')}.\n"
        "Ce fichier démontre uniquement le transport d'un artefact.\n",
        encoding="utf-8",
    )
    return path

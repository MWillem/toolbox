from __future__ import annotations

import os
from pathlib import Path
import stat


SENSITIVE_ENV_NAMES = {
    "AWS_SECRET_ACCESS_KEY",
    "DATABASE_URL",
    "GITHUB_TOKEN",
    "OPENAI_API_KEY",
    "PRIVATE_KEY",
    "SECRET_KEY",
}


def audit_path(path: Path) -> dict[str, object]:
    info = path.stat()
    mode = stat.filemode(info.st_mode)
    findings = []
    if path.is_file() and bool(info.st_mode & stat.S_IWOTH):
        findings.append(
            {
                "severity": "élevée",
                "title": "Fichier modifiable par tous",
                "detail": f"Le mode {mode} autorise l'écriture par les autres utilisateurs.",
            }
        )
    if path.is_dir() and bool(info.st_mode & stat.S_IWOTH):
        findings.append(
            {
                "severity": "élevée",
                "title": "Répertoire modifiable par tous",
                "detail": f"Le mode {mode} permet à d'autres utilisateurs d'y créer ou modifier des fichiers.",
            }
        )
    if path.name.startswith(".") and path.is_file():
        findings.append(
            {
                "severity": "information",
                "title": "Fichier caché",
                "detail": "Vérifier qu'il ne contient pas de secret ou de configuration sensible.",
            }
        )
    if path.suffix.lower() in {".env", ".key", ".pem", ".p12", ".pfx"}:
        findings.append(
            {
                "severity": "moyenne",
                "title": "Type de fichier potentiellement sensible",
                "detail": f"L'extension {path.suffix or path.name} mérite des permissions restrictives.",
            }
        )
    return {
        "path": str(path.resolve()),
        "type": "répertoire" if path.is_dir() else "fichier",
        "mode": mode,
        "size": info.st_size,
        "findings": findings,
    }


def audit_local_configuration() -> dict[str, object]:
    sensitive_names = sorted(
        name
        for name in os.environ
        if name.upper() in SENSITIVE_ENV_NAMES
        or any(marker in name.upper() for marker in ("TOKEN", "SECRET", "PASSWORD", "PRIVATE_KEY"))
    )
    path_entries = [Path(item) for item in os.environ.get("PATH", "").split(os.pathsep) if item]
    missing_entries = [str(item) for item in path_entries if not item.exists()]
    duplicate_entries = sorted(
        {str(item) for item in path_entries if path_entries.count(item) > 1}
    )
    findings = []
    if sensitive_names:
        findings.append(
            {
                "severity": "moyenne",
                "title": "Variables sensibles présentes",
                "detail": f"{len(sensitive_names)} nom(s) détecté(s), sans lire leurs valeurs.",
            }
        )
    if missing_entries:
        findings.append(
            {
                "severity": "faible",
                "title": "Entrées PATH inexistantes",
                "detail": f"{len(missing_entries)} chemin(s) ne sont plus valides.",
            }
        )
    if duplicate_entries:
        findings.append(
            {
                "severity": "information",
                "title": "Entrées PATH dupliquées",
                "detail": f"{len(duplicate_entries)} chemin(s) apparaissent plusieurs fois.",
            }
        )
    return {
        "sensitive_variable_names": sensitive_names,
        "missing_path_entries": missing_entries,
        "duplicate_path_entries": duplicate_entries,
        "findings": findings,
    }

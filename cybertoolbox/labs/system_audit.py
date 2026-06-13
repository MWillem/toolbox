from __future__ import annotations

import os
import platform
import shutil
import sys


def audit_system() -> list[tuple[str, str]]:
    checks = [
        ("Système", f"{platform.system()} {platform.release()}"),
        ("Architecture", platform.machine() or "inconnue"),
        ("Python", platform.python_version()),
        ("Utilisateur privilégié", "oui" if _is_privileged() else "non"),
        ("Git disponible", "oui" if shutil.which("git") else "non"),
        ("SSH disponible", "oui" if shutil.which("ssh") else "non"),
        ("Environnement Termux", "oui" if "com.termux" in os.environ.get("PREFIX", "") else "non"),
    ]
    if sys.version_info < (3, 10):
        checks.append(("Alerte", "Python 3.10 ou plus récent est recommandé."))
    return checks


def _is_privileged() -> bool:
    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0

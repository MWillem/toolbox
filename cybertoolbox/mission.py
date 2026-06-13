from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
import json
from pathlib import Path
import re


MISSIONS_DIR = Path(__file__).resolve().parent.parent / "missions"


@dataclass
class Mission:
    name: str
    scope: str
    authorization: str
    started_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    hosts: list[dict[str, str]] = field(default_factory=list)
    target: str = ""
    services: list[dict[str, object]] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def save(self) -> Path:
        MISSIONS_DIR.mkdir(parents=True, exist_ok=True)
        slug = re.sub(r"[^a-z0-9]+", "-", self.name.lower()).strip("-") or "mission"
        path = MISSIONS_DIR / f"{slug}.json"
        path.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path) -> "Mission":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(**data)


def service_recommendations(services: list[dict[str, object]]) -> list[str]:
    recommendations = []
    for service in services:
        port = int(service["port"])
        name = str(service["service"]).lower()
        if port in {21, 23}:
            recommendations.append(f"Remplacer ou désactiver {name} sur le port {port}, non chiffré.")
        elif port in {80, 8080}:
            recommendations.append(f"Vérifier la redirection HTTPS et les en-têtes du service web sur {port}.")
        elif port == 22:
            recommendations.append("Vérifier les clés SSH, l'authentification par mot de passe et les restrictions d'accès.")
        elif port == 445:
            recommendations.append("Limiter SMB au réseau nécessaire et vérifier la version du protocole.")
        else:
            recommendations.append(f"Confirmer le besoin métier et les mises à jour du service {name} sur {port}.")
    return list(dict.fromkeys(recommendations))

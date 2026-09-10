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


def mission_templates() -> list[dict[str, object]]:
    return [
        {
            "id": "local-network-baseline",
            "name": "Baseline reseau local",
            "scope": "Reseau prive autorise",
            "objective": "Identifier les appareils actifs, les services ouverts et les premieres hypotheses.",
            "tools": ["Scanner IP", "Scan ports", "Device Profiler", "Rapports"],
            "steps": [
                "Confirmer le perimetre autorise.",
                "Lancer une decouverte reseau locale.",
                "Profiler un appareil observe.",
                "Generer les correlations puis compiler un rapport.",
            ],
            "expected_evidence": ["Artefacts device/service", "Timeline", "Correlation NAS/routeur/camera si applicable"],
            "safety": "Pas de scan Internet, pas d'exploitation, pas de tentative d'authentification.",
        },
        {
            "id": "wireless-observation",
            "name": "Observation radio Wi-Fi Bluetooth",
            "scope": "Appareil courant et signaux visibles",
            "objective": "Observer ce que l'OS expose sur les reseaux Wi-Fi et appareils Bluetooth proches.",
            "tools": ["Wi-Fi Analyzer", "Bluetooth Radar", "Timeline", "Correlation"],
            "steps": [
                "Verifier les permissions localisation/proximite.",
                "Lancer Wi-Fi Analyzer.",
                "Lancer Bluetooth Radar.",
                "Comparer les observations avec l'heure et le lieu volontaire.",
            ],
            "expected_evidence": ["SSID/BSSID si disponible", "RSSI", "Appareils Bluetooth connus/visibles"],
            "safety": "Observation uniquement : aucune connexion forcee, desauthentification ou appairage.",
        },
        {
            "id": "public-exposure-check",
            "name": "Ressource publique exposee",
            "scope": "URL, dossier ou partage explicitement fourni",
            "objective": "Verifier ce qui est lisible sans contournement et le transformer en observation.",
            "tools": ["Public Exposure Viewer", "Reports", "Timeline"],
            "steps": [
                "Saisir uniquement une ressource autorisee.",
                "Inspecter les metadonnees et ressources visibles.",
                "Ajouter les constats a la timeline.",
                "Compiler un rapport de restitution.",
            ],
            "expected_evidence": ["Liste publique", "Metadonnees", "Recommandations"],
            "safety": "Pas de brute force, fuzzing, crawling profond ou aspiration massive.",
        },
        {
            "id": "traffic-reading-lab",
            "name": "Lecture trafic pedagogique",
            "scope": "Logs fournis ou demo locale",
            "objective": "Lire des flux comme un mini Wireshark sans capture active.",
            "tools": ["Packet Observer", "Timeline", "Reports"],
            "steps": [
                "Coller des lignes de trafic ou utiliser la demo.",
                "Identifier protocoles, sens et flags TCP.",
                "Transformer les resumes humains en observations.",
                "Documenter les limites, notamment HTTPS.",
            ],
            "expected_evidence": ["Protocoles", "Flags TCP", "Timeline humaine"],
            "safety": "Pas de capture interface, pas de dechiffrement HTTPS.",
        },
        {
            "id": "qr-nfc-awareness",
            "name": "QR/NFC awareness lab",
            "scope": "Payloads pedagogiques et tags autorises",
            "objective": "Comprendre les contenus scannables et leurs risques avant ouverture.",
            "tools": ["QR Code", "NFC Tools", "Hash / Crypto"],
            "steps": [
                "Generer un QR URL de demonstration.",
                "Decoder un QR Wi-Fi ou NDEF hex de lab.",
                "Comparer encodage, hash et chiffrement demo.",
                "Ajouter une note de recommandation au rapport.",
            ],
            "expected_evidence": ["Contenu decode", "Niveau de risque URL", "Lecon securite"],
            "safety": "Payload inoffensif uniquement, aucun tag tiers non autorise.",
        },
    ]


def create_mission_from_template(template_id: str) -> Path:
    templates = {str(item["id"]): item for item in mission_templates()}
    template = templates.get(template_id)
    if template is None:
        raise ValueError("Template de mission inconnu.")
    mission = Mission(
        name=str(template["name"]),
        scope=str(template["scope"]),
        authorization="Mission pedagogique locale ou explicitement autorisee.",
        observations=[
            "Objectif: " + str(template["objective"]),
            "Outils: " + ", ".join(str(item) for item in template["tools"]),
            "Limite: " + str(template["safety"]),
        ],
        recommendations=[str(item) for item in template["steps"]],
    )
    return mission.save()


def list_missions() -> list[Path]:
    if not MISSIONS_DIR.exists():
        return []
    return sorted(MISSIONS_DIR.glob("*.json"), reverse=True)


def rename_mission(path: Path, name: str) -> Path:
    _ensure_mission_path(path)
    clean = re.sub(r"[^a-zA-Z0-9._-]+", "-", name.strip()).strip("-")
    if not clean:
        raise ValueError("Le nouveau nom ne peut pas être vide.")
    destination = path.with_name(f"{clean}.json")
    _ensure_mission_path(destination)
    if destination.exists():
        raise ValueError("Une mission porte déjà ce nom.")
    mission = Mission.load(path)
    mission.name = name.strip()
    destination.write_text(
        json.dumps(asdict(mission), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    path.unlink()
    return destination


def delete_mission(path: Path) -> None:
    _ensure_mission_path(path)
    path.unlink()


def delete_all_missions() -> int:
    missions = list_missions()
    for path in missions:
        path.unlink()
    return len(missions)


def _ensure_mission_path(path: Path) -> None:
    root = MISSIONS_DIR.resolve()
    resolved = path.resolve()
    if resolved.parent != root or resolved.suffix.lower() != ".json":
        raise ValueError("Mission invalide.")

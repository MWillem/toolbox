from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
import json
from pathlib import Path
import re
import secrets
from typing import Any


RECORDS_DIR = Path(__file__).resolve().parent.parent / "donnees"
RECORD_TYPES = {"artifact", "event", "correlation"}
TYPE_DIRS = {
    "artifact": "artifacts",
    "event": "events",
    "correlation": "correlations",
}


@dataclass
class Artifact:
    kind: str
    source: str
    title: str
    summary: str
    value: str = ""
    confidence: str = "faible"
    risk: str = "info"
    scope: str = "local_authorized"
    tags: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    id: str = field(default_factory=lambda: _identifier("art"))


@dataclass
class TimelineEvent:
    source: str
    event_type: str
    description: str
    level: str = "info"
    artifact_id: str = ""
    link: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    id: str = field(default_factory=lambda: _identifier("evt"))


@dataclass
class Correlation:
    title: str
    hypothesis: str
    confidence: str = "faible"
    severity: str = "info"
    related_artifacts: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    id: str = field(default_factory=lambda: _identifier("cor"))


def save_record(record: Artifact | TimelineEvent | Correlation, root: Path = RECORDS_DIR) -> Path:
    payload = asdict(record)
    record_type = _record_type(payload)
    directory = _type_dir(record_type, root)
    directory.mkdir(parents=True, exist_ok=True)
    title = payload.get("title") or payload.get("description") or record_type
    slug = _slug(str(title))
    path = directory / f"{payload['created_at'].replace(':', '')}-{payload['id']}-{slug}.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def list_records(record_type: str | None = None, root: Path = RECORDS_DIR) -> list[Path]:
    if record_type is not None:
        directory = _type_dir(record_type, root)
        return sorted(directory.glob("*.json"), reverse=True) if directory.exists() else []
    paths: list[Path] = []
    for item in RECORD_TYPES:
        paths.extend(list_records(item, root))
    return sorted(paths, reverse=True)


def load_record(path: Path, root: Path = RECORDS_DIR) -> dict[str, Any]:
    _ensure_record_path(path, root)
    payload = json.loads(path.read_text(encoding="utf-8"))
    _record_type(payload)
    return payload


def delete_record(path: Path, root: Path = RECORDS_DIR) -> None:
    _ensure_record_path(path, root)
    path.unlink()


def delete_all_records(record_type: str | None = None, root: Path = RECORDS_DIR) -> int:
    paths = list_records(record_type, root)
    for path in paths:
        path.unlink()
    return len(paths)


def record_display_name(payload: dict[str, Any]) -> str:
    label = str(payload.get("title") or payload.get("description") or payload.get("kind") or "record")
    date = str(payload.get("created_at", "")).replace("T", " ")
    return f"{label} | {date}"


def records_summary(root: Path = RECORDS_DIR) -> dict[str, int]:
    return {
        "artifacts": len(list_records("artifact", root)),
        "events": len(list_records("event", root)),
        "correlations": len(list_records("correlation", root)),
    }


def save_recon_records(
    categories: dict[str, dict[str, Any]],
    *,
    subject: str,
    scope: str = "local_authorized",
    root: Path = RECORDS_DIR,
) -> dict[str, list[dict[str, Any]]]:
    artifacts: list[Artifact] = []
    events: list[TimelineEvent] = []
    correlations: list[Correlation] = []

    for category, section in categories.items():
        items = section.get("items", [])
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            artifact = _artifact_from_recon_item(category, section, item, subject, scope)
            artifacts.append(artifact)
            events.append(
                TimelineEvent(
                    source="scanner",
                    event_type=artifact.kind,
                    description=artifact.summary,
                    level=_event_level(artifact.risk),
                    artifact_id=artifact.id,
                    link="/reports",
                )
            )
            correlations.extend(_correlations_for_artifact(artifact))

    saved_artifacts = [_save_and_load(item, root) for item in artifacts]
    saved_events = [_save_and_load(item, root) for item in events]
    saved_correlations = [_save_and_load(item, root) for item in correlations]
    return {
        "artifacts": saved_artifacts,
        "events": saved_events,
        "correlations": saved_correlations,
    }


def _artifact_from_recon_item(
    category: str,
    section: dict[str, Any],
    item: dict[str, Any],
    subject: str,
    scope: str,
) -> Artifact:
    title = str(section.get("title") or category)
    source = str(section.get("engine") or "scanner")
    if category == "network":
        address = _first(item, "address", "ip", "host")
        hostname = _first(item, "hostname", "name")
        summary = f"Appareil actif detecte: {address or hostname or subject}"
        return Artifact(
            kind="device",
            source=source,
            title=address or hostname or title,
            summary=summary,
            value=address or hostname,
            confidence="moyenne" if address else "faible",
            risk="info",
            scope=scope,
            tags=["network", "device"],
            data=item,
        )
    if category == "ports":
        port = _first(item, "port")
        service = _first(item, "service", "product") or "service inconnu"
        risk = _port_risk(port)
        return Artifact(
            kind="service",
            source=source,
            title=f"{_first(item, 'address') or subject}:{port}",
            summary=f"Port ouvert detecte: {port}/tcp {service}",
            value=str(port),
            confidence="moyenne",
            risk=risk,
            scope=scope,
            tags=["port", "service"],
            data=item,
        )
    if category == "wifi":
        ssid = _first(item, "ssid", "name") or "Reseau masque"
        security = _first(item, "security") or "inconnu"
        risk = "attention" if security.lower() in {"open", "ouvert", "none", "aucun"} else "info"
        return Artifact(
            kind="wifi_network",
            source=source,
            title=ssid,
            summary=f"Reseau Wi-Fi visible: {ssid} ({security})",
            value=ssid,
            confidence="moyenne",
            risk=risk,
            scope=scope,
            tags=["wifi", "radio", "approximate_position"],
            data=item,
        )
    if category == "bluetooth":
        name = _first(item, "name", "alias", "address", "mac") or "Bluetooth inconnu"
        return Artifact(
            kind="bluetooth_device",
            source=source,
            title=name,
            summary=f"Appareil Bluetooth observe: {name}",
            value=name,
            confidence="faible",
            risk="info",
            scope=scope,
            tags=["bluetooth", "radio", "proximity"],
            data=item,
        )
    if category == "http":
        finding = _first(item, "finding", "title", "header", "name") or "Observation HTTP"
        return Artifact(
            kind="http_observation",
            source=source,
            title=finding,
            summary=f"Observation HTTP passive: {finding}",
            value=finding,
            confidence="moyenne",
            risk="attention" if _has_negative_signal(item) else "info",
            scope=scope,
            tags=["http", "passive"],
            data=item,
        )
    return Artifact(
        kind=category,
        source=source,
        title=title,
        summary=f"Observation {category} collectee",
        value=subject,
        scope=scope,
        tags=[category],
        data=item,
    )


def _correlations_for_artifact(artifact: Artifact) -> list[Correlation]:
    data = artifact.data
    correlations: list[Correlation] = []
    if artifact.kind == "service":
        port = str(data.get("port", ""))
        if port in {"21", "23", "445", "3389", "5900", "6379"}:
            correlations.append(
                Correlation(
                    title="Port sensible expose",
                    hypothesis=f"Le service {port}/tcp augmente la surface d'exposition.",
                    confidence="moyenne",
                    severity="attention",
                    related_artifacts=[artifact.id],
                    evidence=[artifact.summary],
                    recommendations=["Verifier le besoin metier et filtrer l'acces au perimetre autorise."],
                )
            )
        service_text = " ".join(str(data.get(key, "")) for key in ("service", "product", "version")).lower()
        if port == "554" or "rtsp" in service_text:
            correlations.append(
                Correlation(
                    title="Camera probable",
                    hypothesis="Un service RTSP peut indiquer une camera ou un flux multimedia.",
                    confidence="moyenne",
                    severity="info",
                    related_artifacts=[artifact.id],
                    evidence=[artifact.summary],
                    recommendations=["Verifier uniquement les metadonnees publiques ou les acces legitimes."],
                )
            )
    if artifact.kind == "wifi_network" and artifact.risk == "attention":
        correlations.append(
            Correlation(
                title="Reseau Wi-Fi ouvert ou faible",
                hypothesis="La configuration de securite Wi-Fi semble absente ou faible.",
                confidence="faible",
                severity="attention",
                related_artifacts=[artifact.id],
                evidence=[artifact.summary],
                recommendations=["Documenter le reseau et confirmer le chiffrement depuis une source autorisee."],
            )
        )
    return correlations


def _first(item: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _has_negative_signal(item: dict[str, Any]) -> bool:
    text = " ".join(str(value).lower() for value in item.values())
    return any(token in text for token in ("missing", "absent", "faible", "insecure", "risque"))


def _port_risk(port: str) -> str:
    return "attention" if str(port) in {"21", "23", "445", "3389", "5900", "6379"} else "info"


def _event_level(risk: str) -> str:
    return {"critique": "critique", "attention": "attention"}.get(risk, "info")


def _save_and_load(record: Artifact | TimelineEvent | Correlation, root: Path) -> dict[str, Any]:
    return load_record(save_record(record, root), root)


def _record_type(payload: dict[str, Any]) -> str:
    if "event_type" in payload:
        return "event"
    if "hypothesis" in payload:
        return "correlation"
    if "kind" in payload and "data" in payload:
        return "artifact"
    raise ValueError("Record invalide.")


def _type_dir(record_type: str, root: Path) -> Path:
    if record_type not in RECORD_TYPES:
        raise ValueError("Type de record invalide.")
    return root / TYPE_DIRS[record_type]


def _ensure_record_path(path: Path, root: Path) -> None:
    resolved_root = root.resolve()
    resolved = path.resolve()
    if resolved.suffix.lower() != ".json" or resolved_root not in resolved.parents:
        raise ValueError("Record invalide.")
    parent = resolved.parent.name
    if parent not in TYPE_DIRS.values():
        raise ValueError("Record invalide.")


def _identifier(prefix: str) -> str:
    return f"{prefix}-{datetime.now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(3)}"


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:80] or "record"

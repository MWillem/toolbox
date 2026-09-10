from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import secrets
from typing import Any


HISTORY_DIR = Path(__file__).resolve().parent.parent / "historique"
KINDS = {"discovery", "port_scan"}


def save_history(
    kind: str,
    subject: str,
    engine: str,
    results: list[dict[str, Any]],
    *,
    ports: str = "",
    label: str = "",
    root: Path = HISTORY_DIR,
) -> Path:
    if kind not in KINDS:
        raise ValueError("Type d'historique invalide.")
    root.mkdir(parents=True, exist_ok=True)
    created_at = datetime.now().isoformat(timespec="seconds")
    identifier = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)
    payload = {
        "id": identifier,
        "kind": kind,
        "label": label.strip() or subject,
        "subject": subject,
        "ports": ports,
        "engine": engine,
        "created_at": created_at,
        "results": results,
    }
    path = root / f"{identifier}-{kind}.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def list_history(kind: str | None = None, root: Path = HISTORY_DIR) -> list[Path]:
    if kind is not None and kind not in KINDS:
        raise ValueError("Type d'historique invalide.")
    if not root.exists():
        return []
    paths = sorted(root.glob("*.json"), reverse=True)
    if kind is None:
        return paths
    return [path for path in paths if load_history(path, root)["kind"] == kind]


def load_history(path: Path, root: Path = HISTORY_DIR) -> dict[str, Any]:
    _ensure_history_path(path, root)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("kind") not in KINDS or not isinstance(payload.get("results"), list):
        raise ValueError("Fiche d'historique invalide.")
    return payload


def rename_history(path: Path, label: str, root: Path = HISTORY_DIR) -> None:
    clean = label.strip()
    if not clean:
        raise ValueError("Le nouveau nom ne peut pas être vide.")
    payload = load_history(path, root)
    payload["label"] = clean[:120]
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def delete_history(path: Path, root: Path = HISTORY_DIR) -> None:
    _ensure_history_path(path, root)
    path.unlink()


def delete_all_history(kind: str | None = None, root: Path = HISTORY_DIR) -> int:
    paths = list_history(kind, root)
    for path in paths:
        path.unlink()
    return len(paths)


def latest_history(
    kind: str,
    subject: str | None = None,
    root: Path = HISTORY_DIR,
) -> tuple[Path, dict[str, Any]] | None:
    for path in list_history(kind, root):
        payload = load_history(path, root)
        if subject is None or payload["subject"] == subject:
            return path, payload
    return None


def compare_port_scans(
    previous: dict[str, Any],
    current_results: list[dict[str, Any]],
) -> dict[str, list[str]]:
    def normalize(items: list[dict[str, Any]]) -> dict[int, str]:
        return {
            int(item["port"]): " ".join(
                str(item.get(key, "")).strip()
                for key in ("service", "product", "version")
                if str(item.get(key, "")).strip()
            ) or "inconnu"
            for item in items
        }

    before = normalize(previous.get("results", []))
    after = normalize(current_results)
    opened = [f"{port}/tcp {after[port]}" for port in sorted(after.keys() - before.keys())]
    closed = [f"{port}/tcp {before[port]}" for port in sorted(before.keys() - after.keys())]
    changed = [
        f"{port}/tcp : {before[port]} -> {after[port]}"
        for port in sorted(before.keys() & after.keys())
        if before[port] != after[port]
    ]
    return {"opened": opened, "closed": closed, "changed": changed}


def history_display_name(payload: dict[str, Any]) -> str:
    date = str(payload.get("created_at", "")).replace("T", " ")
    label = str(payload.get("label") or payload.get("subject") or "Sans nom")
    return f"{label} | {date}"


def _ensure_history_path(path: Path, root: Path) -> None:
    resolved_root = root.resolve()
    resolved = path.resolve()
    if resolved.parent != resolved_root or resolved.suffix.lower() != ".json":
        raise ValueError("Fiche d'historique invalide.")

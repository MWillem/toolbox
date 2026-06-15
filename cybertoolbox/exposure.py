from __future__ import annotations

from collections import Counter
from typing import Any

from .history import list_history, load_history


RISKY_PORTS = {
    21: ("moyenne", "FTP non chiffré"),
    23: ("élevée", "Telnet non chiffré"),
    445: ("moyenne", "SMB à limiter au réseau nécessaire"),
    3389: ("moyenne", "RDP à filtrer et renforcer"),
    5900: ("moyenne", "VNC à protéger"),
    6379: ("élevée", "Redis ne devrait généralement pas être exposé"),
}


def exposure_inventory() -> dict[str, Any]:
    assets: dict[str, dict[str, Any]] = {}
    service_counts: Counter[str] = Counter()
    for path in list_history("port_scan"):
        payload = load_history(path)
        subject = str(payload["subject"])
        if subject in assets:
            continue
        services = payload.get("results", [])
        findings = []
        for service in services:
            port = int(service["port"])
            name = str(service.get("service") or "inconnu")
            service_counts[name] += 1
            if port in RISKY_PORTS:
                severity, message = RISKY_PORTS[port]
                findings.append(
                    {"severity": severity, "port": port, "message": message}
                )
        assets[subject] = {
            "label": payload.get("label", subject),
            "last_seen": payload.get("created_at", ""),
            "ports": payload.get("ports", ""),
            "services": services,
            "findings": findings,
        }
    return {
        "assets": assets,
        "asset_count": len(assets),
        "service_count": sum(len(item["services"]) for item in assets.values()),
        "top_services": service_counts.most_common(8),
        "scope": "Historique local des scans explicitement autorisés",
    }

from __future__ import annotations

from datetime import datetime, timezone
import socket
import ssl


def dns_lookup(hostname: str) -> dict[str, object]:
    infos = socket.getaddrinfo(hostname, None)
    addresses = sorted({info[4][0] for info in infos})
    canonical = socket.getfqdn(hostname)
    return {"hostname": hostname, "canonical": canonical, "addresses": addresses}


def inspect_tls(hostname: str, port: int = 443, timeout: float = 5.0) -> dict[str, object]:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as secure:
            certificate = secure.getpeercert()
            cipher = secure.cipher()
            protocol = secure.version()

    not_after = certificate.get("notAfter", "")
    expiry = ssl.cert_time_to_seconds(not_after) if not_after else None
    days_left = None
    if expiry is not None:
        days_left = int((expiry - datetime.now(timezone.utc).timestamp()) // 86400)
    return {
        "hostname": hostname,
        "port": port,
        "protocol": protocol,
        "cipher": cipher[0] if cipher else "inconnu",
        "subject": _name_to_dict(certificate.get("subject", ())),
        "issuer": _name_to_dict(certificate.get("issuer", ())),
        "not_after": not_after,
        "days_left": days_left,
        "san": [value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"],
    }


def _name_to_dict(value: tuple[tuple[tuple[str, str], ...], ...]) -> dict[str, str]:
    return {key: item for group in value for key, item in group}

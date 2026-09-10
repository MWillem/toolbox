from __future__ import annotations

from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


RECOMMENDED_HEADERS = {
    "content-security-policy": "Réduit le risque d'injection de contenu.",
    "x-content-type-options": "Empêche l'interprétation MIME inattendue.",
    "referrer-policy": "Limite les informations transmises dans le Referer.",
    "permissions-policy": "Contrôle l'accès aux fonctions du navigateur.",
}


def fetch_headers(url: str, timeout: float = 5.0) -> tuple[int, dict[str, str]]:
    if not url.startswith(("http://", "https://")):
        raise ValueError("L'URL doit commencer par http:// ou https://.")
    request = Request(url, method="HEAD", headers={"User-Agent": "CyberToolbox/2.13"})
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers.items())
    except HTTPError as exc:
        return exc.code, dict(exc.headers.items())
    except URLError as exc:
        raise ValueError(f"Connexion impossible : {exc.reason}") from exc


def analyze_headers(headers: dict[str, str], https: bool) -> list[str]:
    normalized = {key.lower(): value for key, value in headers.items()}
    findings = []
    for header, explanation in RECOMMENDED_HEADERS.items():
        if header not in normalized:
            findings.append(f"Absent : {header} - {explanation}")
    if https and "strict-transport-security" not in normalized:
        findings.append("Absent : strict-transport-security - Force l'utilisation de HTTPS.")
    return findings

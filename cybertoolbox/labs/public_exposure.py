from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


MAX_PREVIEW_BYTES = 120_000
MAX_ITEMS = 40


def inspect_public_exposure(target: str, *, timeout: float = 6.0) -> dict[str, Any]:
    """Inspect resources that are already readable without bypass.

    This helper does not brute force, enumerate hidden paths, crawl deeply, or
    authenticate. It only reads the exact URL/path provided by the user.
    """
    value = target.strip()
    if not value:
        raise ValueError("Indiquez une URL, un chemin local ou un partage fourni.")
    if value.startswith(("http://", "https://")):
        return _inspect_http(value, timeout)
    return _inspect_path(value)


def _inspect_http(url: str, timeout: float) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": "reconSC-PublicExposure/1.0"})
    try:
        with urlopen(request, timeout=timeout) as response:
            status = response.status
            headers = dict(response.headers.items())
            content = response.read(MAX_PREVIEW_BYTES + 1)
    except HTTPError as exc:
        status = exc.code
        headers = dict(exc.headers.items())
        content = exc.read(MAX_PREVIEW_BYTES + 1)
    except URLError as exc:
        raise ValueError(f"Ressource inaccessible : {exc.reason}") from exc

    truncated = len(content) > MAX_PREVIEW_BYTES
    content = content[:MAX_PREVIEW_BYTES]
    content_type = headers.get("Content-Type", "")
    text = _decode_preview(content, content_type)
    parser = _LinkParser(url)
    if "html" in content_type.lower() or text.lstrip().startswith("<"):
        parser.feed(text)
    directory_listing = _looks_like_directory_listing(text, parser.links)
    resources = parser.links[:MAX_ITEMS]
    findings = []
    if directory_listing:
        findings.append("Index de dossier HTTP probablement visible.")
    if status in {200, 206} and not resources:
        findings.append("Ressource lisible directement sans authentification detectee.")
    return {
        "mode": "public_exposure",
        "target": url,
        "kind": "http",
        "status": status,
        "content_type": content_type or "inconnu",
        "directory_listing": directory_listing,
        "resources": resources,
        "metadata": {
            "server": headers.get("Server", ""),
            "last_modified": headers.get("Last-Modified", ""),
            "content_length": headers.get("Content-Length", ""),
            "truncated_preview": truncated,
        },
        "preview": text[:2000],
        "findings": findings,
        "recommendations": _recommendations(directory_listing, resources, content_type),
        "limitations": _limitations(),
    }


def _inspect_path(value: str) -> dict[str, Any]:
    path = Path(value).expanduser()
    try:
        exists = path.exists()
    except OSError as exc:
        raise ValueError(f"Chemin inaccessible : {exc}") from exc
    if not exists:
        raise ValueError("Chemin ou partage introuvable depuis cet appareil.")
    if path.is_dir():
        items = []
        for child in sorted(path.iterdir(), key=lambda item: item.name.lower())[:MAX_ITEMS]:
            try:
                stat = child.stat()
            except OSError:
                continue
            items.append(
                {
                    "name": child.name,
                    "type": "dossier" if child.is_dir() else "fichier",
                    "size": stat.st_size,
                    "modified": int(stat.st_mtime),
                }
            )
        return {
            "mode": "public_exposure",
            "target": value,
            "kind": "path",
            "directory_listing": True,
            "resources": items,
            "metadata": {"items_listed": len(items), "max_items": MAX_ITEMS},
            "preview": "",
            "findings": ["Dossier lisible depuis la session courante."],
            "recommendations": [
                "Verifier que ce partage/dossier est volontairement public.",
                "Documenter les droits et retirer les fichiers sensibles.",
            ],
            "limitations": _limitations(),
        }
    stat = path.stat()
    preview = ""
    if stat.st_size <= MAX_PREVIEW_BYTES and _is_previewable(path):
        preview = path.read_text(encoding="utf-8", errors="replace")[:2000]
    return {
        "mode": "public_exposure",
        "target": value,
        "kind": "file",
        "directory_listing": False,
        "resources": [],
        "metadata": {"name": path.name, "size": stat.st_size, "modified": int(stat.st_mtime)},
        "preview": preview,
        "findings": ["Fichier lisible depuis la session courante."],
        "recommendations": ["Verifier que ce fichier est volontairement public avant rapport."],
        "limitations": _limitations(),
    }


class _LinkParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        data = dict(attrs)
        href = data.get("href")
        if not href or href.startswith(("#", "javascript:", "mailto:")):
            return
        label = data.get("title") or href
        self.links.append({"name": label.strip()[:120], "url": urljoin(self.base_url, href)})


def _decode_preview(content: bytes, content_type: str) -> str:
    charset = "utf-8"
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("charset="):
            charset = part.split("=", 1)[1].strip() or "utf-8"
    return content.decode(charset, errors="replace")


def _looks_like_directory_listing(text: str, links: list[dict[str, str]]) -> bool:
    lowered = text[:4000].lower()
    markers = ("index of /", "directory listing for", "parent directory", "name last modified")
    return any(marker in lowered for marker in markers) or len(links) >= 8


def _recommendations(directory_listing: bool, resources: list[dict[str, Any]], content_type: str) -> list[str]:
    recommendations = []
    if directory_listing:
        recommendations.append("Desactiver l'indexation automatique si elle n'est pas volontaire.")
    if resources:
        recommendations.append("Revoir les fichiers listes et retirer toute donnee sensible.")
    if "json" in content_type.lower() or "xml" in content_type.lower():
        recommendations.append("Verifier que les donnees exposees par l'API sont publiques.")
    return recommendations or ["Aucun contournement detecte : documenter seulement ce qui est volontairement accessible."]


def _limitations() -> list[str]:
    return [
        "Aucun brute force, fuzzing, contournement ou scan de chemins caches.",
        "Aucune aspiration massive automatique.",
        "Les resultats prouvent uniquement ce que cette session peut lire.",
    ]


def _is_previewable(path: Path) -> bool:
    return path.suffix.lower() in {".txt", ".log", ".json", ".csv", ".md", ".html", ".xml"}

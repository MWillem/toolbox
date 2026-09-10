from __future__ import annotations

from datetime import datetime
from html import escape
import json
from pathlib import Path
import re


REPORTS_DIR = Path(__file__).resolve().parent.parent / "rapports"


def save_report(title: str, sections: list[tuple[str, str]]) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-") or "rapport"
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = REPORTS_DIR / f"{timestamp}-{slug}.md"

    lines = [
        f"# {title}",
        "",
        f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}.",
        "",
    ]
    for heading, content in sections:
        lines.extend((f"## {heading}", "", content.strip(), ""))
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def save_professional_report(
    title: str,
    scope: str,
    summary: str,
    findings: list[dict[str, str]],
    recommendations: list[str],
    limitations: str,
) -> Path:
    severity_order = {"critique": 0, "élevée": 1, "moyenne": 2, "faible": 3, "information": 4}
    ordered = sorted(findings, key=lambda item: severity_order.get(item.get("severity", ""), 9))
    finding_text = "\n\n".join(
        (
            f"### {index}. {item.get('title', 'Observation')}\n\n"
            f"- **Sévérité** : {item.get('severity', 'information')}\n"
            f"- **Preuve** : {item.get('evidence', item.get('detail', 'Non renseignée'))}\n"
            f"- **Impact** : {item.get('impact', 'À évaluer selon le contexte.')}"
        )
        for index, item in enumerate(ordered, start=1)
    ) or "Aucune observation significative."
    recommendation_text = "\n".join(f"- {item}" for item in recommendations) or "- Maintenir la surveillance."
    return save_report(
        title,
        [
            ("Résumé exécutif", summary),
            ("Périmètre et autorisation", scope),
            ("Constats techniques", finding_text),
            ("Recommandations", recommendation_text),
            ("Limites", limitations),
        ],
    )


def list_reports() -> list[Path]:
    if not REPORTS_DIR.exists():
        return []
    return sorted(REPORTS_DIR.glob("*.md"), reverse=True)


def read_report(path: Path) -> str:
    _ensure_report_path(path)
    return path.read_text(encoding="utf-8")


def delete_report(path: Path) -> None:
    _ensure_report_path(path)
    path.unlink()


def rename_report(path: Path, name: str) -> Path:
    _ensure_report_path(path)
    clean = re.sub(r"[^a-zA-Z0-9._-]+", "-", name.strip()).strip("-")
    if not clean:
        raise ValueError("Le nouveau nom ne peut pas être vide.")
    destination = path.with_name(f"{clean}.md")
    _ensure_report_path(destination)
    if destination.exists():
        raise ValueError("Un rapport porte déjà ce nom.")
    return path.rename(destination)


def delete_all_reports() -> int:
    if not REPORTS_DIR.exists():
        return 0
    reports = [
        path
        for path in REPORTS_DIR.iterdir()
        if path.is_file() and path.suffix.lower() in {".md", ".html", ".json"}
    ]
    for path in reports:
        path.unlink()
    return len(reports)


def merge_reports(paths: list[Path], name: str) -> Path:
    if not paths:
        raise ValueError("Sélectionnez au moins un rapport.")
    sections = []
    for path in paths:
        sections.append((path.name, read_report(path)))
    sections.append(("Conclusion", "À compléter avec vos observations et recommandations."))
    return save_report(name, sections)


def export_report(path: Path, output_format: str) -> Path:
    content = read_report(path)
    if output_format == "json":
        output = path.with_suffix(".json")
        payload = {"name": path.stem, "source": path.name, "content": content}
        output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return output
    if output_format == "html":
        output = path.with_suffix(".html")
        body = escape(content)
        output.write_text(
            "<!doctype html><html lang=\"fr\"><meta charset=\"utf-8\">"
            "<title>Rapport Cyber Toolbox</title>"
            "<style>body{max-width:900px;margin:40px auto;font:16px system-ui;"
            "line-height:1.5;padding:0 20px}pre{white-space:pre-wrap}</style>"
            f"<body><pre>{body}</pre></body></html>",
            encoding="utf-8",
        )
        return output
    raise ValueError("Format accepté : json ou html.")


def _ensure_report_path(path: Path) -> None:
    reports_root = REPORTS_DIR.resolve()
    resolved = path.resolve()
    if resolved.parent != reports_root or resolved.suffix.lower() != ".md":
        raise ValueError("Rapport invalide.")

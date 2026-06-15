from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path


SETTINGS_PATH = Path(__file__).resolve().parent.parent / ".cybertoolbox.json"


@dataclass
class Settings:
    language: str = "fr"
    report_mode: str = "ask"
    theme: str = "violet"
    glass_effect: bool = True
    default_ports: str = "1-1024"
    prefer_nmap: bool = True
    show_lessons: bool = True
    internet_correlation: bool = False
    scan_timeout: float = 0.4

    def validate(self) -> None:
        if self.language not in {"fr", "en"}:
            raise ValueError("Langue acceptée : fr ou en.")
        if self.report_mode not in {"ask", "auto", "off"}:
            raise ValueError("Mode de rapport accepté : ask, auto ou off.")
        if self.theme not in {"violet", "github", "terminal", "ocean", "amber"}:
            raise ValueError("Thème accepté : violet, github, terminal, ocean ou amber.")
        if not 0.1 <= self.scan_timeout <= 5.0:
            raise ValueError("Le délai de scan doit être compris entre 0.1 et 5 secondes.")


def load_settings(path: Path = SETTINGS_PATH) -> Settings:
    if not path.exists():
        return Settings()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        known = {key: value for key, value in payload.items() if key in Settings.__dataclass_fields__}
        settings = Settings(**known)
        settings.validate()
        return settings
    except (ValueError, TypeError, json.JSONDecodeError):
        return Settings()


def save_settings(settings: Settings, path: Path = SETTINGS_PATH) -> Path:
    settings.validate()
    path.write_text(json.dumps(asdict(settings), ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def settings_summary(settings: Settings) -> list[tuple[str, str]]:
    return [
        ("Langue / Language", settings.language),
        ("Rapports", settings.report_mode),
        ("Thème", settings.theme),
        ("Effet verre", "oui" if settings.glass_effect else "non"),
        ("Ports par défaut", settings.default_ports),
        ("Préférer Nmap", "oui" if settings.prefer_nmap else "non"),
        ("Afficher les explications", "oui" if settings.show_lessons else "non"),
        ("Corrélation DNS réseau/Internet", "oui" if settings.internet_correlation else "non"),
        ("Délai TCP", f"{settings.scan_timeout} s"),
    ]

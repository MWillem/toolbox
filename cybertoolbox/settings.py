from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path


SETTINGS_PATH = Path(__file__).resolve().parent.parent / ".cybertoolbox.json"


@dataclass
class Settings:
    language: str = "fr"
    report_mode: str = "ask"
    theme: str = "core"
    app_color_mode: str = "auto"
    map_color_mode: str = "auto"
    glass_effect: bool = True
    glass_opacity: float = 0.46
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
        if self.theme not in {"core", "violet", "github", "terminal", "ocean", "amber"}:
            raise ValueError("Thème accepté : core, violet, github, terminal, ocean ou amber.")
        if self.app_color_mode not in {"auto", "dark", "light"}:
            raise ValueError("Mode app accepté : auto, dark ou light.")
        if self.map_color_mode not in {"auto", "day", "night"}:
            raise ValueError("Mode carte accepté : auto, day ou night.")
        if not 0.15 <= self.glass_opacity <= 0.95:
            raise ValueError("L'opacité du verre doit être comprise entre 0.15 et 0.95.")
        if not 0.1 <= self.scan_timeout <= 5.0:
            raise ValueError("Le délai de scan doit être compris entre 0.1 et 5 secondes.")


def load_settings(path: Path = SETTINGS_PATH) -> Settings:
    if not path.exists():
        return Settings()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        known = {key: value for key, value in payload.items() if key in Settings.__dataclass_fields__}
        defaults = Settings()
        settings = Settings(**{**asdict(defaults), **known})
        try:
            settings.validate()
        except ValueError:
            settings = defaults
            for key, value in known.items():
                candidate = Settings(**{**asdict(settings), key: value})
                try:
                    candidate.validate()
                except (TypeError, ValueError):
                    continue
                settings = candidate
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
        ("Mode app", settings.app_color_mode),
        ("Mode carte", settings.map_color_mode),
        ("Effet verre", "oui" if settings.glass_effect else "non"),
        ("Opacité du verre", f"{settings.glass_opacity:.2f}"),
        ("Ports par défaut", settings.default_ports),
        ("Préférer Nmap", "oui" if settings.prefer_nmap else "non"),
        ("Afficher les explications", "oui" if settings.show_lessons else "non"),
        ("Corrélation DNS réseau/Internet", "oui" if settings.internet_correlation else "non"),
        ("Délai TCP", f"{settings.scan_timeout} s"),
    ]

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .labs.local_lab import prepare_lab
from .labs.log_analysis import analyze_log
from .labs.payloads import analyze_payload_file
from .labs.script_analysis import analyze_script


WATCHDOG_BANNER = r"""
 __        ___  _____ ____ _   _ ____   ___   ____
 \ \      / / \|_   _/ ___| | | |  _ \ / _ \ / ___|
  \ \ /\ / / _ \ | || |   | |_| | | | | | | | |  _
   \ V  V / ___ \| || |___|  _  | |_| | |_| | |_| |
    \_/\_/_/   \_\_| \____|_| |_|____/ \___/ \____|

       MODE WATCHDOG - OPERATION SIGNAL FANTOME
"""


@dataclass
class WatchdogOperation:
    workspace: Path
    artifacts: dict[str, Path] = field(default_factory=dict)
    log_result: dict[str, object] = field(default_factory=dict)
    payload_result: dict[str, object] = field(default_factory=dict)
    script_result: dict[str, object] = field(default_factory=dict)

    def prepare(self) -> None:
        self.artifacts = prepare_lab(self.workspace)
        self.log_result = analyze_log(self.artifacts["log"])
        self.payload_result = analyze_payload_file(self.artifacts["payload"])
        self.script_result = analyze_script(self.artifacts["script"])

    def expected_source(self) -> str:
        failed = self.log_result.get("failed_ips", {})
        return max(failed, key=failed.get) if failed else ""

    def technical_findings(self) -> list[dict[str, str]]:
        findings = [
            {
                "severity": str(item["severity"]),
                "title": str(item["title"]),
                "evidence": str(item["detail"]),
                "impact": "Activité à corréler avec les comptes, systèmes et horaires concernés.",
            }
            for item in self.log_result.get("findings", [])
        ]
        for indicator in self.payload_result.get("findings", []):
            findings.append(
                {
                    "severity": "moyenne",
                    "title": "Indicateur dans le payload factice",
                    "evidence": str(indicator),
                    "impact": "Peut signaler un téléchargement, une exécution ou une communication réseau.",
                }
            )
        for item in self.script_result.get("findings", []):
            findings.append(
                {
                    "severity": str(item["severity"]),
                    "title": str(item["title"]),
                    "evidence": str(item["detail"]),
                    "impact": str(item["impact"]),
                }
            )
        return findings


def answer_matches(value: str, expected: str) -> bool:
    return value.strip().lower() == expected.strip().lower()


def contains_expected_indicators(answer: str, indicators: list[str]) -> bool:
    normalized = answer.lower()
    keywords = {
        "Téléchargement de contenu distant": ("télécharg", "curl", "wget"),
        "Exécution PowerShell": ("powershell",),
        "Primitive de connexion réseau": ("connexion", "réseau", "socket"),
    }
    matched = 0
    for indicator in indicators:
        if any(keyword in normalized for keyword in keywords.get(indicator, ())):
            matched += 1
    return matched >= min(2, len(indicators))

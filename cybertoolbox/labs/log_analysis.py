from __future__ import annotations

from collections import Counter
from pathlib import Path
import re


FAILED_LOGIN = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)")
SUCCESS_LOGIN = re.compile(r"Accepted \S+ for (\S+) from ([0-9a-fA-F:.]+)")
WEB_ERROR = re.compile(r'"(?:GET|POST|PUT|DELETE) ([^ ]+) HTTP/[^"]+" (4\d\d|5\d\d)')
SUSPICIOUS_PATHS = ("../", "/admin", "/.env", "wp-login", "cmd=", "<script")


def analyze_log(path: Path) -> dict[str, object]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    failed_ips: Counter[str] = Counter()
    successes = []
    web_errors: Counter[str] = Counter()
    suspicious = []

    for number, line in enumerate(lines, start=1):
        failed = FAILED_LOGIN.search(line)
        if failed:
            failed_ips[failed.group(2)] += 1
        success = SUCCESS_LOGIN.search(line)
        if success:
            successes.append({"line": number, "user": success.group(1), "ip": success.group(2)})
        web = WEB_ERROR.search(line)
        if web:
            web_errors[web.group(2)] += 1
        if any(marker.lower() in line.lower() for marker in SUSPICIOUS_PATHS):
            suspicious.append({"line": number, "text": line[:240]})

    findings = []
    for ip, count in failed_ips.most_common():
        severity = "élevée" if count >= 5 else "moyenne"
        findings.append(
            {
                "severity": severity,
                "title": "Échecs d'authentification répétés",
                "detail": f"{count} échec(s) depuis {ip}.",
            }
        )
    for login in successes:
        if failed_ips[login["ip"]]:
            findings.append(
                {
                    "severity": "élevée",
                    "title": "Connexion réussie après des échecs",
                    "detail": f"Utilisateur {login['user']} depuis {login['ip']} à la ligne {login['line']}.",
                }
            )
    if suspicious:
        findings.append(
            {
                "severity": "moyenne",
                "title": "Requêtes web suspectes",
                "detail": f"{len(suspicious)} ligne(s) contiennent des chemins ou paramètres sensibles.",
            }
        )
    return {
        "line_count": len(lines),
        "failed_ips": dict(failed_ips),
        "web_errors": dict(web_errors),
        "suspicious_lines": suspicious,
        "findings": findings,
    }

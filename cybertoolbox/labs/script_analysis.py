from __future__ import annotations

import ast
from pathlib import Path
import re


RULES = {
    r"\beval\s*\(": ("élevée", "Évaluation dynamique", "eval peut exécuter une chaîne comme du code."),
    r"\bexec\s*\(": ("élevée", "Exécution dynamique", "exec peut exécuter du code construit à l'exécution."),
    r"shell\s*=\s*True": ("élevée", "Sous-processus via shell", "Une entrée non maîtrisée peut devenir une injection de commande."),
    r"\bos\.system\s*\(": ("moyenne", "Commande système", "Vérifier que la commande ne contient aucune entrée utilisateur."),
    r"\bsubprocess\.(?:run|Popen|call)\s*\(": (
        "information",
        "Création de sous-processus",
        "Contrôler les arguments, les délais et les codes de retour.",
    ),
    r"\brequests\.(?:get|post|put|delete)\s*\(": (
        "information",
        "Communication HTTP",
        "Vérifier les délais, TLS et la validation des données.",
    ),
    r"\b(?:pickle|marshal)\.loads?\s*\(": (
        "élevée",
        "Désérialisation risquée",
        "Ne jamais désérialiser une source non fiable.",
    ),
    r"\binput\s*\(": ("information", "Entrée utilisateur", "Valider la donnée avant toute utilisation sensible."),
}


def analyze_script(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8", errors="replace")
    findings = []
    lines = text.splitlines()
    for pattern, (severity, title, explanation) in RULES.items():
        regex = re.compile(pattern)
        for number, line in enumerate(lines, start=1):
            if regex.search(line):
                findings.append(
                    {
                        "severity": severity,
                        "title": title,
                        "detail": f"Ligne {number} : {line.strip()[:160]}",
                        "impact": explanation,
                    }
                )

    imports = []
    syntax_error = None
    if path.suffix.lower() == ".py":
        try:
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.append(node.module)
        except SyntaxError as exc:
            syntax_error = f"Ligne {exc.lineno} : {exc.msg}"

    return {
        "path": str(path),
        "line_count": len(lines),
        "imports": sorted(set(imports)),
        "syntax_error": syntax_error,
        "findings": findings,
    }

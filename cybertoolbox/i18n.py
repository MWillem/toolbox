from __future__ import annotations


TRANSLATIONS = {
    "fr": {
        "menu_watchdog": "Mode Watchdog",
        "menu_mission": "Mission guidée complète",
        "menu_mapping": "Mappage réseau - hôtes actifs",
        "menu_scan": "Scan de ports - Nmap",
        "menu_lab": "Laboratoire local",
        "menu_password": "Lab mots de passe",
        "menu_reports": "Gestion des rapports",
        "menu_manual": "Manuel et parcours guidé",
        "menu_tools": "Outils complémentaires",
        "menu_settings": "Paramètres",
        "menu_overview": "Vue globale des capacités",
        "quit": "Quitter",
        "choice": "Entrez votre choix",
        "invalid": "Choix invalide.",
        "report_question": "Générer un rapport pour cette opération ? [o/N] : ",
        "report_skipped": "Rapport non généré.",
    },
    "en": {
        "menu_watchdog": "Watchdog mode",
        "menu_mission": "Full guided mission",
        "menu_mapping": "Network mapping - active hosts",
        "menu_scan": "Port scan - Nmap",
        "menu_lab": "Local laboratory",
        "menu_password": "Password lab",
        "menu_reports": "Report management",
        "menu_manual": "Manual and guided path",
        "menu_tools": "Additional tools",
        "menu_settings": "Settings",
        "menu_overview": "Application capabilities",
        "quit": "Quit",
        "choice": "Enter your choice",
        "invalid": "Invalid choice.",
        "report_question": "Generate a report for this operation? [y/N]: ",
        "report_skipped": "Report not generated.",
    },
}


def translate(language: str, key: str) -> str:
    return TRANSLATIONS.get(language, TRANSLATIONS["fr"]).get(key, key)

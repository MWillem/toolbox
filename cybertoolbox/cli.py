from __future__ import annotations

import argparse
from getpass import getpass
import hashlib
import os
from pathlib import Path
import shutil
import sys
import textwrap

from . import __version__
from .device_profile import DeviceProfile, build_device_profile
from .guide import format_guide, full_manual
from .i18n import translate
from .mission import Mission, service_recommendations
from .labs.cracking import crack_demo_hash
from .labs.crypto_basics import (
    base64_decode,
    base64_encode,
    concepts_summary,
    xor_decrypt,
    xor_encrypt,
)
from .labs.file_audit import audit_local_configuration, audit_path
from .labs.hashing import ALGORITHMS, hash_file, hash_text
from .labs.http_headers import analyze_headers, fetch_headers
from .labs.local_lab import prepare_lab, serve_lab
from .labs.log_analysis import analyze_log
from .labs.network import discover_hosts, scan_ports
from .labs.network_info import dns_lookup, inspect_tls
from .labs.passwords import analyze_password
from .labs.payloads import analyze_payload_file, create_harmless_payload
from .labs.script_analysis import analyze_script
from .labs.system_audit import audit_system
from .labs.wireless import bluetooth_inventory, wifi_inventory
from .reports import (
    delete_report,
    export_report,
    list_reports,
    merge_reports,
    read_report,
    save_professional_report as write_professional_report,
    save_report as write_report,
)
from .safety import parse_ports
from .settings import Settings, load_settings, save_settings, settings_summary
from .watchdog import (
    WATCHDOG_BANNER,
    WatchdogOperation,
    answer_matches,
    contains_expected_indicators,
)
from .webapp import serve_gui

SETTINGS = load_settings()


BANNER = r"""
  _____ ___   ___  _     ____   _____  __
 |_   _/ _ \ / _ \| |   | __ ) / _ \ \/ /
   | || | | | | | | |   |  _ \| | | \  /
   | || |_| | |_| | |___| |_) | |_| /  \
   |_| \___/ \___/|_____|____/ \___/_/\_\

       CYBER LEARNING TOOLBOX 2.6
"""

TITLES = {
    "mapping": r"""
  __  __    _    ____  ____ ___ _   _  ____
 |  \/  |  / \  |  _ \|  _ \_ _| \ | |/ ___|
 | |\/| | / _ \ | |_) | |_) | ||  \| | |  _
 | |  | |/ ___ \|  __/|  __/| || |\  | |_| |
 |_|  |_/_/   \_\_|   |_|  |___|_| \_|\____|
""",
    "ports": r"""
  ____   ___  ____ _____ ____
 |  _ \ / _ \|  _ \_   _/ ___|
 | |_) | | | | |_) || | \___ \
 |  __/| |_| |  _ < | |  ___) |
 |_|    \___/|_| \_\|_| |____/
""",
    "password": r"""
  ____   _    ____ ______        _____  ____  ____
 |  _ \ / \  / ___/ ___\ \      / / _ \|  _ \|  _ \
 | |_) / _ \ \___ \___ \\ \ /\ / / | | | |_) | | | |
 |  __/ ___ \ ___) |__) |\ V  V /| |_| |  _ <| |_| |
 |_| /_/   \_\____/____/  \_/\_/  \___/|_| \_\____/
""",
    "payload": r"""
  ____   _ __   ___     ___    _    ____
 |  _ \ / \\ \ / / |   / _ \  / \  |  _ \
 | |_) / _ \\ V /| |  | | | |/ _ \ | | | |
 |  __/ ___ \| | | |__| |_| / ___ \| |_| |
 |_| /_/   \_\_| |_____\___/_/   \_\____/
""",
    "reports": r"""
  ____  _____ ____   ___  ____ _____ ____
 |  _ \| ____|  _ \ / _ \|  _ \_   _/ ___|
 | |_) |  _| | |_) | | | | |_) || | \___ \
 |  _ <| |___|  __/| |_| |  _ < | |  ___) |
 |_| \_\_____|_|    \___/|_| \_\|_| |____/
""",
}

TERMS = """
************************ CONDITIONS D'UTILISATION ************************

Cette toolbox est destinée à l'apprentissage et aux audits explicitement
autorisés. Vous devez limiter chaque action au périmètre convenu, respecter
la loi et protéger les données rencontrées.

La découverte et le scan sont limités aux réseaux privés. Les exercices de
mots de passe et de payloads s'exécutent uniquement en laboratoire local.
Le profil d'un appareil réel exige l'accord de son propriétaire ou responsable.
Les fiches décrivent des actifs techniques et ne doivent pas servir à profiler
ou suivre une personne.
**************************************************************************
"""


COMPACT_BANNER = """
╔══════════════════════════════╗
║  CYBER LEARNING TOOLBOX 2.6  ║
╚══════════════════════════════╝
"""

COMPACT_TERMS = """
CONDITIONS D'UTILISATION

Usage pédagogique et audits explicitement autorisés uniquement.
Les scans restent limités aux réseaux privés. Les exercices de mots
de passe et payloads restent locaux. Aucun profil personnel ni suivi.
"""


def terminal_width() -> int:
    return max(20, shutil.get_terminal_size(fallback=(80, 24)).columns)


def clear_screen() -> None:
    if sys.stdout.isatty():
        os.system("cls" if os.name == "nt" else "clear")


def responsive_banner(banner: str, compact: str, minimum_width: int = 64) -> str:
    return banner if terminal_width() >= minimum_width else compact


def print_menu_item(key: str, label: str) -> None:
    prefix = f"{key}. "
    lines = textwrap.wrap(
        label,
        width=max(12, terminal_width() - len(prefix) - 1),
        break_long_words=False,
        break_on_hyphens=False,
    ) or [label]
    print(prefix + lines[0])
    for line in lines[1:]:
        print(" " * len(prefix) + line)


def print_title(name: str) -> None:
    if terminal_width() >= 64:
        print(TITLES[name])
    else:
        print(f"\n=== {name.upper()} ===")


def print_terms() -> None:
    print(TERMS if terminal_width() >= 72 else COMPACT_TERMS)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybertoolbox",
        description="Toolbox guidée pour apprendre les bases d'un audit de cybersécurité.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")

    discover = sub.add_parser("discover", help="Découvrir les hôtes actifs d'un réseau privé")
    discover.add_argument("network")
    discover.add_argument("--authorized", action="store_true")

    scan = sub.add_parser("scan", help="Scanner les ports d'une cible privée avec Nmap si disponible")
    scan.add_argument("target")
    scan.add_argument("--ports", default=None)
    scan.add_argument("--authorized", action="store_true")

    crack = sub.add_parser("crack", help="Lab hors ligne d'attaque par dictionnaire")
    crack.add_argument("hash")
    crack.add_argument("wordlist", type=Path)
    crack.add_argument("--algorithm", choices=ALGORITHMS, default="sha256")

    payload = sub.add_parser("payload", help="Analyser un fichier comme payload potentiel")
    payload.add_argument("file", type=Path)

    sub.add_parser("mission", help="Lancer un audit guidé de bout en bout")
    sub.add_parser("watchdog", help="Lancer l'opération scénarisée locale")

    profile = sub.add_parser("profile", help="Créer le profil technique d'un appareil autorisé")
    profile.add_argument("target")
    profile.add_argument("--ports", default=None)
    profile.add_argument("--authorized", action="store_true")

    asset = sub.add_parser("asset", help="Profiler passivement un domaine public")
    asset.add_argument("hostname")

    sub.add_parser("settings", help="Afficher ou modifier les paramètres")
    sub.add_parser("overview", help="Afficher toutes les capacités de l'application")

    lab_prepare = sub.add_parser("lab-prepare", help="Créer les artefacts du laboratoire local")
    lab_prepare.add_argument("--directory", type=Path, default=Path("lab_workspace"))

    lab_serve = sub.add_parser("lab-serve", help="Lancer le serveur HTTP volontairement incomplet")
    lab_serve.add_argument("--port", type=int, default=8088)

    logs = sub.add_parser("logs", help="Analyser un journal système ou web")
    logs.add_argument("file", type=Path)

    dns = sub.add_parser("dns", help="Résoudre un nom DNS")
    dns.add_argument("hostname")

    tls = sub.add_parser("tls", help="Inspecter un certificat TLS")
    tls.add_argument("hostname")
    tls.add_argument("--port", type=int, default=443)

    permissions = sub.add_parser("permissions", help="Auditer les permissions d'un fichier ou dossier")
    permissions.add_argument("path", type=Path)

    sub.add_parser("config", help="Auditer la configuration locale sans lire les secrets")

    encoding = sub.add_parser("encoding", help="Atelier encodage et chiffrement pédagogique")
    encoding.add_argument("action", choices=("encode", "decode", "encrypt", "decrypt"))
    encoding.add_argument("value")
    encoding.add_argument("--key", default="")

    script = sub.add_parser("script", help="Analyser statiquement un script sans l'exécuter")
    script.add_argument("file", type=Path)

    sub.add_parser("wifi", help="Afficher les informations Wi-Fi autorisées par le système")
    sub.add_parser("bluetooth", help="Afficher les appareils Bluetooth connus du système")

    sub.add_parser("manual", help="Afficher le manuel guidé")
    sub.add_parser("reports", help="Lister les rapports générés")
    sub.add_parser("system", help="Auditer l'environnement local")

    password = sub.add_parser("password", help="Évaluer un mot de passe localement")
    password.add_argument("--value", help=argparse.SUPPRESS)

    hashing = sub.add_parser("hash", help="Calculer un condensat")
    source = hashing.add_mutually_exclusive_group(required=True)
    source.add_argument("--text")
    source.add_argument("--file", type=Path)
    hashing.add_argument("--algorithm", choices=ALGORITHMS, default="sha256")

    headers = sub.add_parser("headers", help="Examiner les en-têtes HTTP de sécurité")
    headers.add_argument("url")
    gui = sub.add_parser("gui", help="Lancer l'interface graphique responsive locale")
    gui.add_argument("--port", type=int, default=8765)
    gui.add_argument("--lan", action="store_true")
    gui.add_argument("--no-browser", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if not args.command:
            return interactive_menu()
        if args.command in {"discover", "scan", "profile"} and not args.authorized:
            raise ValueError("Ajoutez --authorized après avoir vérifié votre autorisation.")
        return run_command(args)
    except (ValueError, OSError) as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nOpération interrompue.")
        return 130


def run_command(args: argparse.Namespace) -> int:
    if args.command == "discover":
        run_mapping(args.network)
    elif args.command == "scan":
        run_scan(args.target, args.ports or SETTINGS.default_ports)
    elif args.command == "crack":
        run_crack_hash(args.hash, args.wordlist, args.algorithm)
    elif args.command == "payload":
        run_payload_analysis(args.file)
    elif args.command == "mission":
        run_mission()
    elif args.command == "watchdog":
        run_watchdog_menu()
    elif args.command == "profile":
        run_device_profile(args.target, args.ports or SETTINGS.default_ports)
    elif args.command == "asset":
        run_public_asset_profile(args.hostname)
    elif args.command == "settings":
        manage_settings()
    elif args.command == "overview":
        show_overview()
    elif args.command == "lab-prepare":
        run_lab_prepare(args.directory)
    elif args.command == "lab-serve":
        serve_lab(args.port)
    elif args.command == "logs":
        run_log_analysis(args.file)
    elif args.command == "dns":
        run_dns(args.hostname)
    elif args.command == "tls":
        run_tls(args.hostname, args.port)
    elif args.command == "permissions":
        run_permissions(args.path)
    elif args.command == "config":
        run_configuration_audit()
    elif args.command == "encoding":
        run_encoding(args.action, args.value, args.key)
    elif args.command == "script":
        run_script_analysis(args.file)
    elif args.command == "wifi":
        run_wireless_inventory("wifi")
    elif args.command == "bluetooth":
        run_wireless_inventory("bluetooth")
    elif args.command == "manual":
        print(full_manual())
    elif args.command == "reports":
        show_reports()
    elif args.command == "system":
        run_system()
    elif args.command == "password":
        run_password(args.value)
    elif args.command == "hash":
        run_hash(args.text, args.file, args.algorithm)
    elif args.command == "headers":
        run_headers(args.url)
    elif args.command == "gui":
        serve_gui(args.port, lan=args.lan, open_browser=not args.no_browser)
    return 0


def run_mapping(network: str, show_lesson: bool = True) -> None:
    if show_lesson and SETTINGS.show_lessons:
        _lesson("mapping")
    hosts, engine = discover_hosts(network, prefer_nmap=SETTINGS.prefer_nmap)
    lines = [f"- `{host['address']}` - {host['hostname']}" for host in hosts]
    if not lines:
        lines = ["- Aucun hôte actif détecté. Certains pare-feu bloquent les sondes."]
    content = "\n".join(lines)
    print(f"Moteur : {engine}")
    print(content)
    _report(
        "Mappage réseau",
        [
            ("Objectif", format_guide("mapping")),
            ("Périmètre", f"Réseau privé autorisé : `{network}`\n\nMoteur : {engine}"),
            ("Hôtes actifs", content),
            ("Interprétation", "Un hôte actif doit encore être analysé avant toute conclusion."),
        ],
    )


def run_scan(target: str, ports_value: str, show_lesson: bool = True) -> None:
    if show_lesson and SETTINGS.show_lessons:
        _lesson("ports")
    ports = parse_ports(ports_value)
    results, engine = scan_ports(
        target,
        ports,
        timeout=SETTINGS.scan_timeout,
        prefer_nmap=SETTINGS.prefer_nmap,
    )
    lines = []
    for item in results:
        parts = (str(item["service"]), str(item["product"]), str(item["version"]))
        detail = " ".join(part for part in parts if part)
        lines.append(f"- `{item['port']}/{item['protocol']}` : {detail or 'inconnu'}")
    if not lines:
        lines = ["- Aucun port ouvert détecté dans la sélection."]
    content = "\n".join(lines)
    print(f"Moteur : {engine}")
    print(content)
    _report(
        "Scan de ports",
        [
            ("Objectif", format_guide("ports")),
            ("Périmètre", f"Cible autorisée : `{target}`\n\nPorts : `{ports_value}`\n\nMoteur : {engine}"),
            ("Services exposés", content),
            ("À vérifier", "Chaque service est-il nécessaire, à jour, filtré et correctement authentifié ?"),
        ],
    )


def run_crack_hash(
    target_hash: str,
    wordlist: Path,
    algorithm: str,
    show_lesson: bool = True,
) -> None:
    if show_lesson:
        _lesson("password")
    candidates = wordlist.read_text(encoding="utf-8", errors="replace").splitlines()
    result = crack_demo_hash(target_hash, candidates, algorithm)
    if result["found"] is None:
        print(f"Non trouvé après {result['tested']} essais en {result['elapsed']} s.")
    else:
        print(f"Trouvé : {result['found']!r} après {result['tested']} essais.")
    _save_cracking_report(result, wordlist.name)


def run_payload_analysis(path: Path, show_lesson: bool = True) -> None:
    if show_lesson:
        _lesson("payload")
    result = analyze_payload_file(path)
    findings = result["findings"] or ["Aucun indicateur simple détecté. Cela ne prouve pas que le fichier est sûr."]
    content = "\n".join(f"- {finding}" for finding in findings)
    print(f"Fichier : {result['name']} ({result['size']} octets)")
    print(f"SHA-256 : {result['sha256']}")
    print(content)
    _report(
        "Analyse de payload",
        [
            ("Objectif", format_guide("payload")),
            ("Artefact", f"`{result['name']}` - {result['size']} octets\n\nSHA-256 : `{result['sha256']}`"),
            ("Indicateurs", content),
            ("Limite", "Cette analyse statique simple ne remplace pas une sandbox ou un antivirus."),
        ],
    )


def run_system() -> None:
    checks = audit_system()
    content = "\n".join(f"- **{name}** : {value}" for name, value in checks)
    print(content)
    _report("Audit du système", [("Résultats", content)])


def run_password(value: str | None = None) -> None:
    password = value if value is not None else getpass("Mot de passe à évaluer (non affiché) : ")
    result = analyze_password(password)
    advice = "\n".join(f"- {item}" for item in result["advice"])
    print(f"Niveau : {result['level']} | Entropie théorique : {result['entropy']} bits")
    print(advice)
    content = (
        f"- Longueur : {result['length']}\n"
        f"- Niveau : {result['level']}\n"
        f"- Entropie théorique : {result['entropy']} bits\n\n"
        f"### Recommandations\n\n{advice}\n\n"
        "_Le mot de passe analysé n'est ni enregistré ni transmis._"
    )
    _report("Analyse de mot de passe", [("Analyse", content)])


def run_hash(text: str | None, file: Path | None, algorithm: str) -> None:
    if file is not None:
        digest = hash_file(file, algorithm)
        source = f"Fichier : `{file.name}`"
    else:
        digest = hash_text(text or "", algorithm)
        source = "Texte fourni localement"
    print(f"{algorithm}: {digest}")
    _report("Atelier intégrité", [("Résultat", f"{source}\n\n`{algorithm}: {digest}`")])


def run_headers(url: str) -> None:
    status, headers = fetch_headers(url)
    findings = analyze_headers(headers, url.startswith("https://"))
    content = "\n".join(f"- {item}" for item in findings) if findings else "- Aucun manque évident détecté."
    print(f"Statut HTTP : {status}")
    print(content)
    professional = [
        {
            "severity": "moyenne",
            "title": item.split(" - ", 1)[0],
            "evidence": item,
            "impact": "Le navigateur dispose de moins de contraintes pour limiter certains contenus ou fuites.",
        }
        for item in findings
    ]
    report_path = _professional_report(
        "Audit des en-têtes HTTP",
        f"URL analysée : `{url}`\n\nStatut HTTP : {status}",
        f"{len(findings)} en-tête(s) recommandé(s) absent(s).",
        professional,
        [
            "Ajouter les en-têtes après validation de leur compatibilité avec l'application.",
            "Tester d'abord la Content-Security-Policy en mode Report-Only.",
            "Réaliser une nouvelle analyse après correction.",
        ],
        "Analyse passive des en-têtes de réponse ; aucun contenu applicatif n'a été testé.",
    )
    _announce_report(report_path)


def run_lab_prepare(directory: Path = Path("lab_workspace")) -> None:
    artifacts = prepare_lab(directory)
    print("Laboratoire préparé :")
    for name, path in artifacts.items():
        print(f"- {name} : {path}")
    print("\nExercices conseillés :")
    print(f"1. Analyser le journal : run.bat logs {artifacts['log']}")
    print(f"2. Identifier le payload : run.bat payload {artifacts['payload']}")
    print(f"3. Auditer le script : run.bat script {artifacts['script']}")
    print("4. Lancer le serveur : run.bat lab-serve")
    print("5. Dans un autre terminal : run.bat headers http://127.0.0.1:8088")


def run_log_analysis(path: Path) -> None:
    result = analyze_log(path)
    findings = result["findings"]
    print(f"{result['line_count']} ligne(s) analysée(s).")
    if findings:
        for finding in findings:
            print(f"- [{finding['severity']}] {finding['title']} : {finding['detail']}")
    else:
        print("- Aucun scénario suspect reconnu.")
    professional = [
        {
            "severity": str(item["severity"]),
            "title": str(item["title"]),
            "evidence": str(item["detail"]),
            "impact": "Peut indiquer une tentative d'accès, une compromission ou une reconnaissance.",
        }
        for item in findings
    ]
    path_report = _professional_report(
        "Analyse de journal",
        f"Fichier local : `{path.name}`",
        f"{result['line_count']} lignes analysées, {len(findings)} constat(s).",
        professional,
        [
            "Corréler les adresses IP avec les autres journaux.",
            "Bloquer temporairement les sources répétitives si le contexte le justifie.",
            "Vérifier les connexions réussies après des échecs.",
        ],
        "Analyse par motifs simples ; les horodatages et le contexte métier doivent être vérifiés.",
    )
    _announce_report(path_report)


def run_dns(hostname: str) -> None:
    result = dns_lookup(hostname)
    addresses = "\n".join(f"- `{address}`" for address in result["addresses"])
    print(f"Nom canonique : {result['canonical']}")
    print(addresses)
    _report(
        "Analyse DNS",
        [
            ("Objectif", "Relier un nom de domaine aux adresses utilisées et vérifier la résolution."),
            ("Résultat", f"Nom canonique : `{result['canonical']}`\n\n{addresses}"),
        ],
    )


def run_tls(hostname: str, port: int = 443) -> None:
    result = inspect_tls(hostname, port)
    summary = (
        f"Protocole : {result['protocol']}\n"
        f"Chiffrement : {result['cipher']}\n"
        f"Expiration : {result['not_after']} ({result['days_left']} jours)\n"
        f"Émetteur : {result['issuer'].get('organizationName', 'inconnu')}"
    )
    print(summary)
    recommendations = ["Renouveler le certificat avant son expiration."]
    if result["days_left"] is not None and int(result["days_left"]) < 30:
        recommendations.insert(0, "Traiter rapidement l'expiration proche du certificat.")
    _report(
        "Inspection TLS",
        [
            ("Cible", f"`{hostname}:{port}`"),
            ("Résultat", summary),
            ("Recommandations", "\n".join(f"- {item}" for item in recommendations)),
        ],
    )


def run_permissions(path: Path) -> None:
    result = audit_path(path)
    findings = result["findings"]
    print(f"Type : {result['type']} | Mode : {result['mode']} | Taille : {result['size']} octets")
    if findings:
        for finding in findings:
            print(f"- [{finding['severity']}] {finding['title']} : {finding['detail']}")
    else:
        print("- Aucun problème simple de permission détecté.")
    professional = [
        {
            "severity": str(item["severity"]),
            "title": str(item["title"]),
            "evidence": str(item["detail"]),
            "impact": "Une permission excessive peut exposer ou permettre la modification de données.",
        }
        for item in findings
    ]
    report_path = _professional_report(
        "Audit de permissions",
        f"Chemin local : `{result['path']}`",
        f"Analyse d'un {result['type']} avec le mode {result['mode']}.",
        professional,
        ["Appliquer le moindre privilège et vérifier les droits après modification."],
        "Sous Windows, les ACL détaillées ne sont pas couvertes par cette première analyse portable.",
    )
    _announce_report(report_path)


def run_configuration_audit() -> None:
    result = audit_local_configuration()
    findings = result["findings"]
    print(f"Variables potentiellement sensibles : {len(result['sensitive_variable_names'])}")
    print(f"Entrées PATH inexistantes : {len(result['missing_path_entries'])}")
    for finding in findings:
        print(f"- [{finding['severity']}] {finding['title']} : {finding['detail']}")
    professional = [
        {
            "severity": str(item["severity"]),
            "title": str(item["title"]),
            "evidence": str(item["detail"]),
            "impact": "Une configuration locale mal maîtrisée peut exposer des secrets ou détourner l'exécution.",
        }
        for item in findings
    ]
    report_path = _professional_report(
        "Audit de configuration locale",
        "Environnement du processus courant. Les valeurs des secrets ne sont jamais consultées.",
        f"{len(findings)} observation(s) de configuration.",
        professional,
        [
            "Stocker les secrets dans un gestionnaire adapté.",
            "Nettoyer les entrées PATH inexistantes ou dupliquées.",
            "Éviter d'exposer durablement des secrets dans les variables globales.",
        ],
        "L'audit reste portable et ne couvre pas toutes les politiques propres au système.",
    )
    _announce_report(report_path)


def run_encoding(action: str, value: str, key: str = "") -> None:
    if action == "encode":
        result = base64_encode(value)
        operation = "Encodage Base64"
    elif action == "decode":
        result = base64_decode(value)
        operation = "Décodage Base64"
    elif action == "encrypt":
        result = xor_encrypt(value, key)
        operation = "Chiffrement XOR pédagogique"
    else:
        result = xor_decrypt(value, key)
        operation = "Déchiffrement XOR pédagogique"
    print(f"{operation} : {result}")
    print(concepts_summary())
    _report(
        "Atelier encodage et chiffrement",
        [
            ("Concepts", concepts_summary()),
            ("Opération", operation),
            (
                "Avertissement",
                "Le XOR répétitif sert uniquement à comprendre la réversibilité. "
                "Il ne protège pas de véritables données.",
            ),
        ],
    )


def run_script_analysis(path: Path) -> None:
    result = analyze_script(path)
    findings = result["findings"]
    print(f"{result['line_count']} ligne(s), {len(findings)} observation(s).")
    if result["imports"]:
        print("Imports : " + ", ".join(result["imports"]))
    if result["syntax_error"]:
        print(f"Erreur de syntaxe : {result['syntax_error']}")
    for finding in findings:
        print(f"- [{finding['severity']}] {finding['title']} : {finding['detail']}")
    report_path = _professional_report(
        "Analyse statique de script",
        f"Fichier local : `{path.name}`",
        f"{result['line_count']} ligne(s) analysée(s), {len(findings)} observation(s).",
        findings,
        [
            "Valider toutes les entrées avant un appel système.",
            "Éviter eval, exec, shell=True et les désérialisations non fiables.",
            "Compléter cette revue automatique par une lecture humaine.",
        ],
        "Analyse par règles simples, sans exécution et sans suivi complet des flux de données.",
    )
    _announce_report(report_path)


def run_mission() -> None:
    print("\n=== MISSION GUIDÉE : CARTOGRAPHIER ET ANALYSER ===")
    print("Cette mission relie découverte, sélection d'une cible, scan et restitution.")
    name = input("Nom de la mission : ").strip() or "Audit guidé"
    scope = input("Réseau privé autorisé (ex. 192.168.1.0/24) : ").strip()
    authorization = input("Référence de l'autorisation (client, lab, ticket...) : ").strip()
    if not authorization:
        raise ValueError("Une référence d'autorisation est nécessaire.")
    if not _authorized():
        return

    mission = Mission(name=name, scope=scope, authorization=authorization)
    mission.hosts, discovery_engine = discover_hosts(scope, prefer_nmap=SETTINGS.prefer_nmap)
    if not mission.hosts:
        mission.observations.append("Aucun hôte actif détecté.")
        mission.save()
        print("Aucun hôte détecté. La mission a été sauvegardée.")
        return

    print(f"\nHôtes détectés avec {discovery_engine} :")
    for index, host in enumerate(mission.hosts, start=1):
        print(f"{index}. {host['address']} - {host['hostname']}")
    try:
        selected = int(input("Hôte à analyser : ")) - 1
        if selected < 0 or selected >= len(mission.hosts):
            raise IndexError
        mission.target = mission.hosts[selected]["address"]
    except (ValueError, IndexError) as exc:
        raise ValueError("Sélection d'hôte invalide.") from exc

    ports_value = (
        input(f"Ports à analyser [{SETTINGS.default_ports}] : ").strip()
        or SETTINGS.default_ports
    )
    mission.services, scan_engine = scan_ports(
        mission.target,
        parse_ports(ports_value),
        timeout=SETTINGS.scan_timeout,
        prefer_nmap=SETTINGS.prefer_nmap,
    )
    mission.recommendations = service_recommendations(mission.services)
    mission.observations.append(
        f"{len(mission.services)} service(s) TCP ouvert(s) détecté(s) avec {scan_engine}."
    )
    session_path = mission.save()

    findings = [
        {
            "severity": "moyenne",
            "title": f"Service {service['service']} exposé sur {service['port']}/tcp",
            "evidence": " ".join(
                value
                for value in (
                    str(service["service"]),
                    str(service.get("product", "")),
                    str(service.get("version", "")),
                )
                if value
            ),
            "impact": "La surface exposée doit être justifiée, mise à jour et filtrée.",
        }
        for service in mission.services
    ]
    report_path = _professional_report(
        mission.name,
        f"Réseau : `{scope}`\n\nCible : `{mission.target}`\n\nAutorisation : {authorization}",
        (
            f"Découverte de {len(mission.hosts)} hôte(s), puis analyse de "
            f"{len(mission.services)} service(s) ouvert(s) sur {mission.target}."
        ),
        findings,
        mission.recommendations,
        "Scan TCP limité aux ports sélectionnés ; aucun test d'exploitation n'a été réalisé.",
    )
    print(f"\nMission sauvegardée : {session_path}")
    _announce_report(report_path, "Rapport final")


def run_device_profile(target: str, ports_value: str) -> DeviceProfile:
    print("\n=== PROFIL TECHNIQUE D'UN APPAREIL AUTORISÉ ===")
    profile = build_device_profile(
        target,
        ports_value,
        timeout=SETTINGS.scan_timeout,
        prefer_nmap=SETTINGS.prefer_nmap,
        allow_internet=SETTINGS.internet_correlation,
    )
    print(f"Nom réseau      : {profile.hostname}")
    print(f"Adresse IP      : {profile.address}")
    print(f"Adresse MAC     : {profile.mac_address or 'indisponible'}")
    print(f"Fabricant       : {profile.manufacturer or 'non déterminé'}")
    print(f"Type probable   : {profile.device_type}")
    print(f"Confiance       : {profile.confidence}")
    print(f"Moteur de scan  : {profile.scan_engine}")
    print("Indices :")
    for evidence in profile.evidence:
        print(f"- {evidence}")
    print("Services :")
    for service in profile.services:
        detail = " ".join(
            value
            for value in (
                str(service.get("service", "")),
                str(service.get("product", "")),
                str(service.get("version", "")),
            )
            if value
        )
        print(f"- {service['port']}/{service['protocol']} : {detail or 'inconnu'}")
    if not profile.services:
        print("- Aucun service sélectionné détecté.")
    print("Limites :")
    for limitation in profile.limitations:
        print(f"- {limitation}")
    if profile.correlations:
        print("Corrélations réseau/Internet autorisées :")
        for correlation in profile.correlations:
            print(f"- {correlation}")

    service_text = "\n".join(
        f"- `{item['port']}/{item['protocol']}` : {item.get('service', 'inconnu')}"
        for item in profile.services
    ) or "- Aucun service sélectionné détecté."
    findings = [
        {
            "severity": "information",
            "title": f"Type probable : {profile.device_type}",
            "evidence": "; ".join(profile.evidence) or "Indices insuffisants",
            "impact": f"Niveau de confiance : {profile.confidence}.",
        }
    ]
    findings.extend(
        {
            "severity": "moyenne",
            "title": f"Service exposé sur {item['port']}/{item['protocol']}",
            "evidence": str(item.get("service", "inconnu")),
            "impact": "Vérifier que ce service est nécessaire, à jour et correctement filtré.",
        }
        for item in profile.services
    )
    report_path = _professional_report(
        f"Profil appareil - {profile.hostname if profile.hostname != '-' else profile.address}",
        (
            f"Appareil autorisé : `{profile.address}`\n\n"
            f"MAC : `{profile.mac_address or 'indisponible'}`\n\n"
            f"Fabricant : {profile.manufacturer or 'non déterminé'}"
            + (
                "\n\nCorrélations : " + "; ".join(profile.correlations)
                if profile.correlations
                else ""
            )
        ),
        (
            f"Type probable : {profile.device_type} ({profile.confidence}). "
            f"{len(profile.services)} service(s) observé(s)."
        ),
        findings,
        service_recommendations(profile.services),
        "\n".join(f"- {item}" for item in profile.limitations),
    )
    _announce_report(report_path)
    return profile


def run_public_asset_profile(hostname: str) -> None:
    if not SETTINGS.internet_correlation:
        raise ValueError(
            "Activez d'abord la corrélation DNS réseau/Internet dans les paramètres."
        )
    print("\n=== PROFIL PASSIF D'UN ACTIF PUBLIC ===")
    dns_result = dns_lookup(hostname)
    tls_result = inspect_tls(hostname, 443)
    status, headers = fetch_headers(f"https://{hostname}")
    header_findings = analyze_headers(headers, https=True)

    print(f"Domaine         : {hostname}")
    print(f"Nom canonique   : {dns_result['canonical']}")
    print("Adresses        : " + ", ".join(str(item) for item in dns_result["addresses"]))
    print(f"TLS             : {tls_result['protocol']} / {tls_result['cipher']}")
    print(f"Expiration      : {tls_result['not_after']} ({tls_result['days_left']} jours)")
    print(f"Statut HTTPS    : {status}")
    for finding in header_findings:
        print(f"- {finding}")

    findings = [
        {
            "severity": "moyenne",
            "title": item.split(" - ", 1)[0],
            "evidence": item,
            "impact": "Protection navigateur absente ou non observée.",
        }
        for item in header_findings
    ]
    if tls_result["days_left"] is not None and int(tls_result["days_left"]) < 30:
        findings.append(
            {
                "severity": "élevée",
                "title": "Expiration TLS proche",
                "evidence": f"{tls_result['days_left']} jours restants.",
                "impact": "Une expiration peut interrompre ou dégrader la confiance dans le service.",
            }
        )
    report_path = _professional_report(
        f"Profil actif public - {hostname}",
        (
            f"Domaine explicitement fourni : `{hostname}`\n\n"
            "Collecte passive DNS, TLS et HTTP."
        ),
        (
            f"{len(dns_result['addresses'])} adresse(s), TLS {tls_result['protocol']}, "
            f"{len(header_findings)} en-tête(s) recommandé(s) absent(s)."
        ),
        findings,
        [
            "Surveiller l'expiration du certificat.",
            "Tester les en-têtes manquants avant leur déploiement.",
            "Comparer les changements DNS dans le temps.",
        ],
        (
            "Aucune attribution personnelle. DNS, CDN, hébergements partagés et proxys "
            "peuvent empêcher toute conclusion sur l'organisation réelle."
        ),
    )
    _announce_report(report_path)


def run_watchdog_menu() -> None:
    clear_screen()
    print(responsive_banner(WATCHDOG_BANNER, "\n=== MODE WATCHDOG ===\n"))
    print_menu_item("1", "Opération Signal Fantôme - scénario fictif local")
    print_menu_item("2", "Profiler un appareil réel autorisé du réseau privé")
    print_menu_item("3", "Profiler passivement un domaine public")
    choice = input("Choix : ").strip()
    if choice == "1":
        run_watchdog_mode()
    elif choice == "2":
        target = input("IP ou nom local de l'appareil : ").strip()
        ports = input(f"Ports [{SETTINGS.default_ports}] : ").strip() or SETTINGS.default_ports
        if _authorized():
            run_device_profile(target, ports)
    elif choice == "3":
        run_public_asset_profile(input("Nom de domaine : ").strip())
    else:
        print("Choix invalide.")


def run_watchdog_mode() -> None:
    clear_screen()
    print(responsive_banner(WATCHDOG_BANNER, "\n=== OPÉRATION SIGNAL FANTÔME ===\n"))
    print(
        "BRIEFING\n"
        "Une activité anormale a été signalée sur le réseau fictif CTOS-LAB.\n"
        "Votre mission : corréler les journaux, qualifier un artefact et repérer\n"
        "une faiblesse dans un script récupéré. Tous les éléments sont locaux.\n"
    )
    if input("Initialiser l'opération ? [o/N] : ").strip().lower() != "o":
        print("Opération annulée.")
        return

    operation = WatchdogOperation(Path("lab_workspace") / "watchdog")
    operation.prepare()
    observations = []

    print("\n[1/3] CORRELATION DES JOURNAUX")
    print(f"{operation.log_result['line_count']} événements chargés.")
    source_answer = input("Quelle IP concentre les échecs puis une connexion réussie ? : ")
    source_ok = answer_matches(source_answer, operation.expected_source())
    if source_ok:
        print("[CONFIRMÉ] Source correctement identifiée.")
    else:
        print(f"[INDICE] La source attendue était {operation.expected_source()}.")
    observations.append(
        f"Source d'authentification identifiée : {operation.expected_source()} "
        f"({'réponse correcte' if source_ok else 'corrigée par le système'})."
    )

    print("\n[2/3] QUALIFICATION DU PAYLOAD")
    print(f"Artefact : {operation.artifacts['payload'].name}")
    indicator_answer = input(
        "Citez au moins deux comportements visibles (ex. téléchargement, PowerShell, réseau) : "
    )
    indicator_ok = contains_expected_indicators(
        indicator_answer,
        [str(item) for item in operation.payload_result["findings"]],
    )
    if indicator_ok:
        print("[CONFIRMÉ] Plusieurs indicateurs ont été reconnus.")
    else:
        print("[INDICE] Recherchez curl, PowerShell et socket dans l'artefact.")
    observations.append(
        "Payload factice : " + ", ".join(str(item) for item in operation.payload_result["findings"])
    )

    print("\n[3/3] REVUE DU SCRIPT")
    risk_answer = input("Quel paramètre rend l'appel subprocess particulièrement risqué ? : ")
    script_ok = "shell=true" in risk_answer.replace(" ", "").lower()
    if script_ok:
        print("[CONFIRMÉ] shell=True augmente le risque d'injection de commande.")
    else:
        print("[INDICE] Le paramètre attendu est shell=True.")
    observations.append("Script : entrée utilisateur transmise à subprocess avec shell=True.")

    correct = sum((source_ok, indicator_ok, script_ok))
    findings = operation.technical_findings()
    report_path = _professional_report(
        "Opération Signal Fantôme",
        "Laboratoire local généré par la Cyber Learning Toolbox.",
        (
            f"Opération terminée : {correct}/3 étape(s) interprétée(s) sans indice. "
            "Les constats techniques ont été vérifiés automatiquement."
        ),
        findings,
        [
            "Examiner les connexions réussies précédées d'échecs.",
            "Isoler et analyser les artefacts avant toute exécution.",
            "Éviter de transmettre une entrée utilisateur à un shell.",
            "Corréler plusieurs sources avant de conclure à une compromission.",
        ],
        "Scénario pédagogique entièrement local ; aucune machine tierce n'a été contactée.",
    )
    print("\n=== OPÉRATION TERMINÉE ===")
    for observation in observations:
        print(f"- {observation}")
    _announce_report(report_path, "Rapport d'opération")


def interactive_menu() -> int:
    clear_screen()
    print(responsive_banner(BANNER, COMPACT_BANNER))
    print_terms()
    if input("Acceptez-vous ces conditions ? [o/N] : ").strip().lower() != "o":
        print("Conditions refusées. Fermeture de la toolbox.")
        return 1

    actions = {
        "1": (translate(SETTINGS.language, "menu_watchdog"), run_watchdog_menu),
        "2": (translate(SETTINGS.language, "menu_mission"), run_mission),
        "3": (translate(SETTINGS.language, "menu_mapping"), _interactive_mapping),
        "4": (translate(SETTINGS.language, "menu_scan"), _interactive_scan),
        "5": (translate(SETTINGS.language, "menu_lab"), _interactive_local_lab),
        "6": (translate(SETTINGS.language, "menu_password"), _interactive_password_lab),
        "7": (translate(SETTINGS.language, "menu_reports"), manage_reports),
        "8": (translate(SETTINGS.language, "menu_manual"), lambda: print(full_manual())),
        "9": (translate(SETTINGS.language, "menu_tools"), _extra_tools),
        "10": (translate(SETTINGS.language, "menu_settings"), manage_settings),
        "11": (translate(SETTINGS.language, "menu_overview"), show_overview),
        "12": ("Interface graphique responsive", _interactive_gui),
    }
    while True:
        clear_screen()
        print(responsive_banner(BANNER, COMPACT_BANNER))
        for key, (label, _) in actions.items():
            print_menu_item(key, label)
        print_menu_item("0", translate(SETTINGS.language, "quit"))
        choice = input(f"\n{translate(SETTINGS.language, 'choice')} : ").strip()
        if choice == "0":
            print("Merci d'avoir utilisé la Cyber Learning Toolbox.")
            return 0
        action = actions.get(choice)
        if not action:
            print(translate(SETTINGS.language, "invalid"))
            input("\nAppuyez sur Entrée pour continuer...")
            continue
        clear_screen()
        try:
            action[1]()
        except (ValueError, OSError) as exc:
            print(f"Erreur : {exc}")
        input("\nAppuyez sur Entrée pour revenir au menu...")


def _interactive_gui() -> None:
    print("\nINTERFACE GRAPHIQUE LOCALE")
    print("Ouverture sur http://127.0.0.1:8765")
    print("Utilisez Ctrl+C pour arrêter le serveur.")
    try:
        serve_gui()
    except KeyboardInterrupt:
        print("\nInterface graphique arrêtée.")


def _interactive_mapping() -> None:
    _lesson("mapping")
    network = input("Réseau privé (ex. 192.168.1.0/24) : ").strip()
    if _authorized():
        run_mapping(network, show_lesson=False)


def _interactive_scan() -> None:
    _lesson("ports")
    target = input("Cible locale/privée : ").strip()
    ports = input(f"Ports [{SETTINGS.default_ports}] : ").strip() or SETTINGS.default_ports
    if _authorized():
        run_scan(target, ports, show_lesson=False)


def _interactive_password_lab() -> None:
    clear_screen()
    _lesson("password")
    print("1. Évaluer la robustesse d'un mot de passe")
    print("2. Démontrer une attaque par dictionnaire sur un hash créé ici")
    choice = input("Choix : ").strip()
    if choice == "1":
        run_password()
        return
    if choice != "2":
        print("Choix invalide.")
        return
    secret = getpass("Mot de passe de démonstration (non affiché) : ")
    target_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    print(f"Hash SHA-256 du lab : {target_hash}")
    wordlist = Path(input("Chemin de la petite liste de candidats : ").strip())
    run_crack_hash(target_hash, wordlist, "sha256", show_lesson=False)


def _interactive_payload_lab() -> None:
    clear_screen()
    _lesson("payload")
    print("1. Analyser statiquement un fichier")
    print("2. Simuler le dépôt d'un payload inoffensif")
    choice = input("Choix : ").strip()
    if choice == "1":
        run_payload_analysis(Path(input("Chemin du fichier : ").strip()), show_lesson=False)
    elif choice == "2":
        path = create_harmless_payload(Path.cwd() / "lab_payload")
        print(f"Artefact inoffensif déposé dans : {path}")
        run_payload_analysis(path, show_lesson=False)
    else:
        print("Choix invalide.")


def _interactive_local_lab() -> None:
    clear_screen()
    print("\nLABORATOIRE LOCAL")
    print_menu_item("1", "Préparer les journaux et payloads pédagogiques")
    print_menu_item("2", "Analyser le journal préparé")
    print_menu_item("3", "Analyser le payload à identifier")
    print_menu_item("4", "Analyser le script volontairement risqué")
    print_menu_item("5", "Lancer le serveur HTTP mal configuré")
    choice = input("Choix : ").strip()
    root = Path("lab_workspace")
    if choice == "1":
        run_lab_prepare(root)
    elif choice == "2":
        run_log_analysis(root / "journal_suspect.log")
    elif choice == "3":
        run_payload_analysis(root / "payload_a_identifier.txt")
    elif choice == "4":
        run_script_analysis(root / "script_a_auditer.py")
    elif choice == "5":
        try:
            serve_lab(8088)
        except KeyboardInterrupt:
            print("\nServeur arrêté.")
    else:
        print("Choix invalide.")


def manage_reports() -> None:
    while True:
        clear_screen()
        print_title("reports")
        print(format_guide("reports"))
        reports = list_reports()
        if not reports:
            print("Aucun rapport disponible.")
            return
        for index, report in enumerate(reports, start=1):
            print(f"{index}. {report.name}")
        print("a. Afficher | f. Fusionner | e. Exporter | s. Supprimer | q. Retour")
        action = input("Action : ").strip().lower()
        if action == "q":
            return
        if action == "a":
            report = _choose_report(reports)
            if report:
                clear_screen()
                print("\n" + read_report(report))
                input("\nAppuyez sur Entrée pour revenir aux rapports...")
        elif action == "s":
            report = _choose_report(reports)
            if report and input(f"Supprimer {report.name} ? [o/N] : ").lower() == "o":
                delete_report(report)
                print("Rapport supprimé.")
        elif action == "f":
            raw = input("Numéros à fusionner, séparés par des virgules : ")
            selected = _select_reports(reports, raw)
            name = input("Titre du rapport fusionné : ").strip() or "Rapport fusionné"
            print(f"Rapport créé : {merge_reports(selected, name)}")
        elif action == "e":
            report = _choose_report(reports)
            if report:
                output_format = input("Format [html/json] : ").strip().lower()
                print(f"Export créé : {export_report(report, output_format)}")
        else:
            print("Action invalide.")


def show_reports() -> None:
    reports = list_reports()
    if not reports:
        print("Aucun rapport.")
        return
    for report in reports:
        print(report)


def run_wireless_inventory(kind: str) -> None:
    result = wifi_inventory() if kind == "wifi" else bluetooth_inventory()
    title = "Inventaire Wi-Fi" if kind == "wifi" else "Inventaire Bluetooth"
    print(f"Moteur : {result['engine']}")
    print(result["description"])
    print(result["output"] or "Aucune information retournée.")
    _report(
        title,
        [
            ("Source", f"{result['engine']} - {result['description']}"),
            ("Résultat brut", str(result["output"] or "Aucune information retournée.")),
            (
                "Limites",
                "Lecture seule des informations exposées par le système. "
                "Aucune capture, association ou surveillance cachée.",
            ),
        ],
    )


def manage_settings() -> None:
    clear_screen()
    print("\n=== PARAMÈTRES ===")
    for index, (name, value) in enumerate(settings_summary(SETTINGS), start=1):
        print(f"{index}. {name} : {value}")
    print("0. Retour sans modification")
    choice = input("Paramètre à modifier : ").strip()
    if choice == "0":
        return
    if choice == "1":
        SETTINGS.language = input("Langue [fr/en] : ").strip().lower()
    elif choice == "2":
        SETTINGS.report_mode = input("Rapports [ask/auto/off] : ").strip().lower()
    elif choice == "3":
        value = input(f"Ports par défaut [{SETTINGS.default_ports}] : ").strip()
        if value:
            parse_ports(value)
            SETTINGS.default_ports = value
    elif choice == "4":
        SETTINGS.prefer_nmap = _ask_boolean("Préférer Nmap lorsqu'il est disponible")
    elif choice == "5":
        SETTINGS.show_lessons = _ask_boolean("Afficher les explications pédagogiques")
    elif choice == "6":
        SETTINGS.internet_correlation = _ask_boolean(
            "Autoriser la corrélation DNS du nom de l'appareil"
        )
    elif choice == "7":
        SETTINGS.scan_timeout = float(input("Délai TCP en secondes [0.1-5] : ").strip())
    else:
        print("Choix invalide.")
        return
    path = save_settings(SETTINGS)
    print(f"Paramètres enregistrés dans {path}.")
    if choice == "1":
        print("La langue complète prendra effet au prochain lancement.")


def show_overview() -> None:
    clear_screen()
    print(
        """
=== VUE GLOBALE DE LA CYBER LEARNING TOOLBOX ===

PARCOURS
- Mode Watchdog fictif : enquête locale sur journaux, payload et script.
- Profil Watchdog réel : fiche technique d'un appareil privé autorisé.
- Profil passif public : DNS, TLS et en-têtes HTTPS d'un domaine fourni.
- Mission guidée : périmètre, découverte, cible, services et recommandations.

RÉSEAU ET ACTIFS
- Découverte d'hôtes privés avec Nmap ou ping.
- Scan TCP et identification de services avec Nmap ou sockets.
- Profil : IP, nom réseau, MAC disponible, fabricant disponible, type probable.
- DNS, TLS, en-têtes HTTP et serveur web local pédagogique.
- Wi-Fi courant/visible et Bluetooth connu, selon les capacités du système.

INVESTIGATION
- Analyse de journaux SSH/web.
- Analyse statique de payloads et scripts, sans exécution.
- Corrélation d'échecs et de connexions réussies.

SYSTÈME ET DONNÉES
- Audit système, configuration, PATH et permissions.
- Hash de textes/fichiers, Base64 et chiffrement XOR pédagogique.
- Lab hors ligne de résistance des mots de passe.

RESTITUTION
- Rapports Markdown professionnels, consultation, fusion, HTML et JSON.
- Génération ask/auto/off selon les paramètres.

LIMITES IMPORTANTES
- Un profil concerne un actif technique, jamais l'identité d'une personne.
- Le type d'appareil est une estimation accompagnée d'un niveau de confiance.
- MAC et fabricant sont surtout disponibles sur le même réseau local.
- Bluetooth et Wi-Fi avancés dépendent du système, des permissions et du matériel.
- Aucune exploitation, persistance ou surveillance cachée n'est réalisée.
"""
    )


def _extra_tools() -> None:
    clear_screen()
    print_menu_item("1", "Audit du système")
    print_menu_item("2", "Empreinte SHA-256 d'un texte")
    print_menu_item("3", "En-têtes HTTP")
    print_menu_item("4", "Résolution DNS")
    print_menu_item("5", "Certificat TLS")
    print_menu_item("6", "Analyse d'un journal")
    print_menu_item("7", "Permissions d'un fichier ou dossier")
    print_menu_item("8", "Configuration locale")
    print_menu_item("9", "Encodage et chiffrement pédagogique")
    print_menu_item("10", "Analyse statique d'un script")
    print_menu_item("11", "Informations Wi-Fi")
    print_menu_item("12", "Appareils Bluetooth connus")
    choice = input("Choix : ").strip()
    if choice == "1":
        run_system()
    elif choice == "2":
        run_hash(input("Texte : "), None, "sha256")
    elif choice == "3":
        run_headers(input("URL : ").strip())
    elif choice == "4":
        run_dns(input("Nom de domaine : ").strip())
    elif choice == "5":
        run_tls(input("Nom de domaine : ").strip())
    elif choice == "6":
        run_log_analysis(Path(input("Chemin du journal : ").strip()))
    elif choice == "7":
        run_permissions(Path(input("Chemin à auditer : ").strip()))
    elif choice == "8":
        run_configuration_audit()
    elif choice == "9":
        _interactive_encoding()
    elif choice == "10":
        run_script_analysis(Path(input("Chemin du script : ").strip()))
    elif choice == "11":
        run_wireless_inventory("wifi")
    elif choice == "12":
        run_wireless_inventory("bluetooth")
    else:
        print("Choix invalide.")


def _interactive_encoding() -> None:
    print(concepts_summary())
    print("1. Encoder en Base64")
    print("2. Décoder du Base64")
    print("3. Chiffrer avec le XOR pédagogique")
    print("4. Déchiffrer avec le XOR pédagogique")
    choice = input("Choix : ").strip()
    actions = {"1": "encode", "2": "decode", "3": "encrypt", "4": "decrypt"}
    action = actions.get(choice)
    if not action:
        print("Choix invalide.")
        return
    value = input("Valeur : ")
    key = getpass("Clé de démonstration : ") if action in {"encrypt", "decrypt"} else ""
    run_encoding(action, value, key)


def _lesson(name: str) -> None:
    print_title(name)
    print(format_guide(name))


def _ask_boolean(label: str) -> bool:
    return input(f"{label} ? [o/N] : ").strip().lower() in {"o", "oui", "y", "yes"}


def _authorized() -> bool:
    answer = input("Confirmez-vous être autorisé sur ce périmètre ? [o/N] : ").strip().lower()
    if answer != "o":
        print("Opération annulée.")
        return False
    return True


def _save_cracking_report(result: dict[str, object], wordlist_name: str) -> None:
    status = "trouvé" if result["found"] is not None else "non trouvé"
    content = (
        f"- Algorithme : {result['algorithm']}\n"
        f"- Dictionnaire : `{wordlist_name}`\n"
        f"- Résultat : {status}\n"
        f"- Candidats testés : {result['tested']}\n"
        f"- Durée : {result['elapsed']} seconde(s)\n\n"
        "_Le mot de passe retrouvé n'est volontairement pas enregistré dans le rapport._"
    )
    _report("Lab résistance des mots de passe", [("Objectif", format_guide("password")), ("Résultat", content)])


def _choose_report(reports: list[Path]) -> Path | None:
    try:
        index = int(input("Numéro du rapport : ")) - 1
    except ValueError:
        print("Numéro invalide.")
        return None
    if index < 0 or index >= len(reports):
        print("Numéro invalide.")
        return None
    return reports[index]


def _select_reports(reports: list[Path], raw: str) -> list[Path]:
    try:
        indices = [int(value.strip()) - 1 for value in raw.split(",")]
        selected = [reports[index] for index in indices if 0 <= index < len(reports)]
    except (ValueError, IndexError) as exc:
        raise ValueError("Sélection de rapports invalide.") from exc
    if not selected:
        raise ValueError("Aucun rapport valide sélectionné.")
    return selected


def _report(title: str, sections: list[tuple[str, str]]) -> None:
    if not _should_generate_report():
        print(translate(SETTINGS.language, "report_skipped"))
        return
    path = write_report(title, sections)
    print(f"Rapport : {path}")


def _professional_report(
    title: str,
    scope: str,
    summary: str,
    findings: list[dict[str, str]],
    recommendations: list[str],
    limitations: str,
) -> Path | None:
    if not _should_generate_report():
        return None
    return write_professional_report(
        title,
        scope,
        summary,
        findings,
        recommendations,
        limitations,
    )


def _should_generate_report() -> bool:
    if SETTINGS.report_mode == "auto":
        return True
    if SETTINGS.report_mode == "off":
        return False
    answer = input(translate(SETTINGS.language, "report_question")).strip().lower()
    return answer in {"o", "oui", "y", "yes"}


def _announce_report(path: Path | None, label: str = "Rapport") -> None:
    if path is None:
        print(translate(SETTINGS.language, "report_skipped"))
    else:
        print(f"{label} : {path}")

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ipaddress
import platform
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET

from cybertoolbox.safety import parse_private_network, resolve_authorized_target


SERVICES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP alternatif",
}

PORT_GUIDE = {
    20: ("FTP-data", "Transfert de données FTP, ancien protocole souvent non chiffré."),
    21: ("FTP", "Transfert de fichiers. Préférer SFTP ou FTPS pour les données sensibles."),
    22: ("SSH/SFTP", "Administration distante et transfert sécurisé."),
    23: ("Telnet", "Administration distante non chiffrée, généralement à désactiver."),
    25: ("SMTP", "Transport des courriels entre serveurs."),
    53: ("DNS", "Résolution des noms de domaine."),
    67: ("DHCP serveur", "Attribution automatique de la configuration réseau."),
    68: ("DHCP client", "Réception de la configuration réseau."),
    80: ("HTTP", "Serveur web non chiffré ou redirection vers HTTPS."),
    110: ("POP3", "Réception de courriels, souvent remplacée par POP3S."),
    123: ("NTP", "Synchronisation de l'heure."),
    135: ("RPC Windows", "Services RPC Microsoft, à limiter aux réseaux nécessaires."),
    139: ("NetBIOS", "Partage Windows historique."),
    143: ("IMAP", "Consultation de courriels, souvent remplacée par IMAPS."),
    161: ("SNMP", "Supervision d'équipements réseau."),
    389: ("LDAP", "Annuaire. LDAP simple peut être non chiffré."),
    443: ("HTTPS", "Serveur web protégé par TLS."),
    445: ("SMB", "Partages de fichiers et services Windows."),
    465: ("SMTPS", "Envoi de courriels avec TLS implicite."),
    587: ("SMTP submission", "Soumission authentifiée de courriels."),
    631: ("IPP/CUPS", "Impression réseau."),
    993: ("IMAPS", "Consultation IMAP chiffrée."),
    995: ("POP3S", "Réception POP3 chiffrée."),
    1433: ("Microsoft SQL Server", "Base de données Microsoft SQL Server."),
    1521: ("Oracle", "Base de données Oracle."),
    3306: ("MySQL/MariaDB", "Base de données MySQL ou MariaDB."),
    3389: ("RDP", "Bureau à distance Windows."),
    5432: ("PostgreSQL", "Base de données PostgreSQL."),
    5900: ("VNC", "Contrôle graphique à distance."),
    6379: ("Redis", "Base clé-valeur, rarement destinée à être exposée."),
    8080: ("HTTP alternatif", "Interface web, proxy ou application de développement."),
    8443: ("HTTPS alternatif", "Interface web TLS sur un port alternatif."),
    9100: ("JetDirect", "Impression réseau directe."),
}


def common_port_guide() -> list[tuple[int, str, str]]:
    return [(port, name, description) for port, (name, description) in PORT_GUIDE.items()]


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def discover_hosts(network_value: str, prefer_nmap: bool = True) -> tuple[list[dict[str, str]], str]:
    network = parse_private_network(network_value)
    if prefer_nmap and nmap_available():
        return _discover_with_nmap(network), "Nmap -sn"
    return _discover_with_ping(network), "ping système (mode de secours)"


def _discover_with_nmap(network: ipaddress.IPv4Network) -> list[dict[str, str]]:
    process = subprocess.run(
        ["nmap", "-sn", "-oG", "-", str(network)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
    )
    if process.returncode != 0:
        raise ValueError(process.stderr.strip() or "Nmap n'a pas pu terminer la découverte.")
    hosts = []
    for line in process.stdout.splitlines():
        match = re.match(r"Host: (\S+) \((.*?)\)\s+Status: Up", line)
        if match:
            hosts.append({"address": match.group(1), "hostname": match.group(2) or "-"})
    return hosts


def _discover_with_ping(network: ipaddress.IPv4Network) -> list[dict[str, str]]:
    def probe(address: ipaddress.IPv4Address) -> dict[str, str] | None:
        if platform.system() == "Windows":
            command = ["ping", "-n", "1", "-w", "500", str(address)]
        else:
            command = ["ping", "-c", "1", "-W", "1", str(address)]
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        if result.returncode == 0:
            try:
                hostname = socket.gethostbyaddr(str(address))[0]
            except socket.herror:
                hostname = "-"
            return {"address": str(address), "hostname": hostname}
        return None

    with ThreadPoolExecutor(max_workers=32) as executor:
        results = executor.map(probe, network.hosts())
    return [result for result in results if result is not None]


def scan_ports(
    target: str,
    ports: list[int],
    timeout: float = 0.4,
    prefer_nmap: bool = True,
) -> tuple[list[dict[str, object]], str]:
    address = resolve_authorized_target(target)[0]
    if prefer_nmap and nmap_available():
        return _scan_with_nmap(address, ports), "Nmap -sV"
    return _scan_with_sockets(address, ports, timeout), "sockets TCP (mode de secours)"


def _scan_with_nmap(address: str, ports: list[int]) -> list[dict[str, object]]:
    command = ["nmap", "-sV", "-Pn", "-p", ",".join(map(str, ports)), "-oX", "-", address]
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
        check=False,
    )
    if process.returncode != 0:
        raise ValueError(process.stderr.strip() or "Nmap n'a pas pu terminer le scan.")
    root = ET.fromstring(process.stdout)
    results = []
    for port_node in root.findall(".//port"):
        state = port_node.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port_node.find("service")
        results.append(
            {
                "port": int(port_node.get("portid", "0")),
                "protocol": port_node.get("protocol", "tcp"),
                "service": service.get("name", "inconnu") if service is not None else "inconnu",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
            }
        )
    return results


def _scan_with_sockets(address: str, ports: list[int], timeout: float) -> list[dict[str, object]]:
    def probe(port: int) -> dict[str, object] | None:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((address, port)) == 0:
                return {
                    "port": port,
                    "protocol": "tcp",
                    "service": SERVICES.get(port, "inconnu"),
                    "product": "",
                    "version": "",
                }
        return None

    with ThreadPoolExecutor(max_workers=min(32, len(ports))) as executor:
        results = executor.map(probe, ports)
    return [result for result in results if result is not None]

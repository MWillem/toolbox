from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET

from .labs.network import scan_ports
from .safety import parse_ports, resolve_authorized_target


@dataclass
class DeviceProfile:
    target: str
    address: str
    hostname: str
    mac_address: str = ""
    manufacturer: str = ""
    device_type: str = "Appareil réseau non déterminé"
    confidence: str = "faible"
    evidence: list[str] = field(default_factory=list)
    services: list[dict[str, object]] = field(default_factory=list)
    scan_engine: str = ""
    correlations: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def build_device_profile(
    target: str,
    ports_value: str,
    timeout: float = 0.4,
    prefer_nmap: bool = True,
    allow_internet: bool = False,
) -> DeviceProfile:
    address = resolve_authorized_target(target)[0]
    try:
        hostname = socket.gethostbyaddr(address)[0]
    except socket.herror:
        hostname = target if target != address else "-"

    services, engine = scan_ports(
        address,
        parse_ports(ports_value),
        timeout=timeout,
        prefer_nmap=prefer_nmap,
    )
    mac, manufacturer = lookup_neighbor(address)
    device_type, confidence, evidence = infer_device_type(hostname, manufacturer, services)
    correlations = []
    if allow_internet and hostname not in {"", "-"}:
        try:
            related = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None)})
            correlations.append(
                f"Résolution DNS de {hostname} : {', '.join(related)}"
            )
        except socket.gaierror:
            correlations.append(f"Aucune résolution DNS supplémentaire pour {hostname}.")
    limitations = [
        "Le type est une estimation technique, pas une identité personnelle.",
        "Les pare-feu et services masqués peuvent réduire la précision.",
    ]
    if not mac:
        limitations.append("Adresse MAC indisponible hors du segment local ou absente du cache voisin.")
    if not manufacturer:
        limitations.append("Fabricant non déterminé sans information Nmap/OUI locale.")
    return DeviceProfile(
        target=target,
        address=address,
        hostname=hostname,
        mac_address=mac,
        manufacturer=manufacturer,
        device_type=device_type,
        confidence=confidence,
        evidence=evidence,
        services=services,
        scan_engine=engine,
        correlations=correlations,
        limitations=limitations,
    )


def lookup_neighbor(address: str) -> tuple[str, str]:
    if shutil.which("nmap"):
        try:
            process = subprocess.run(
                ["nmap", "-sn", "-oX", "-", address],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                check=False,
            )
            if process.returncode == 0:
                root = ET.fromstring(process.stdout)
                mac_node = root.find(".//address[@addrtype='mac']")
                if mac_node is not None:
                    return mac_node.get("addr", ""), mac_node.get("vendor", "")
        except (subprocess.TimeoutExpired, ET.ParseError):
            pass

    commands = (
        ["arp", "-a", address],
        ["ip", "neigh", "show", address],
    )
    for command in commands:
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        match = re.search(r"\b([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\b", process.stdout)
        if match:
            return match.group(1).upper().replace("-", ":"), ""
    return "", ""


def infer_device_type(
    hostname: str,
    manufacturer: str,
    services: list[dict[str, object]],
) -> tuple[str, str, list[str]]:
    products = " ".join(
        f"{item.get('service', '')} {item.get('product', '')} {item.get('version', '')}"
        for item in services
    )
    text = f"{hostname} {manufacturer} {products}".lower()
    ports = {int(item["port"]) for item in services}
    service_names = {str(item.get("service", "")).lower() for item in services}
    scores: dict[str, list[str]] = {}

    def add(kind: str, evidence: str) -> None:
        scores.setdefault(kind, []).append(evidence)

    if any(token in text for token in ("iphone", "android", "pixel", "galaxy", "mobile")):
        add("Téléphone ou tablette", "Nom réseau associé à un appareil mobile")
    if any(token in text for token in ("printer", "imprim", "laserjet", "epson", "brother", "canon")):
        add("Imprimante réseau", "Nom ou fabricant associé à une imprimante")
    if any(token in text for token in ("tv", "chromecast", "roku", "firetv", "apple-tv")):
        add("TV ou appareil multimédia", "Nom réseau associé au multimédia")
    if any(token in text for token in ("router", "gateway", "livebox", "freebox", "fritz")):
        add("Routeur ou passerelle", "Nom réseau associé à une passerelle")
    if any(token in text for token in ("camera", "cam", "doorbell", "ring")):
        add("Caméra ou objet connecté", "Nom réseau associé à une caméra")
    if any(token in text for token in ("microsoft", "windows", "netbios")):
        add("PC ou serveur Windows", "Produit ou service associé à Windows")
    if any(token in text for token in ("cups", "jetdirect", "printer")):
        add("Imprimante réseau", "Produit ou service d'impression identifié")

    if 9100 in ports or 515 in ports or 631 in ports:
        add("Imprimante réseau", "Service d'impression exposé")
    if 445 in ports or 3389 in ports:
        add("PC ou serveur Windows", "Service SMB ou RDP exposé")
    if 22 in ports and ({80, 443} & ports):
        add("Serveur, équipement réseau ou objet connecté", "SSH et interface web exposés")
    if 53 in ports and ({80, 443} & ports):
        add("Routeur, DNS ou passerelle", "DNS et interface web exposés")
    if 554 in ports or "rtsp" in service_names:
        add("Caméra ou appareil multimédia", "Service RTSP exposé")
    if not scores and not services:
        return "Appareil client ou filtré", "faible", ["Aucun service sélectionné n'est exposé"]
    if not scores:
        return "Appareil réseau générique", "faible", ["Services insuffisamment discriminants"]

    device_type, evidence = max(scores.items(), key=lambda item: len(item[1]))
    count = len(evidence)
    confidence = "élevée" if count >= 3 else "moyenne" if count == 2 else "faible"
    return device_type, confidence, evidence

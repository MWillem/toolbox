from __future__ import annotations

from collections import Counter
import re
from typing import Any


DEMO_TRAFFIC = """192.168.1.10 -> 140.82.121.4 TCP 51544 443 SYN github.com
140.82.121.4 -> 192.168.1.10 TCP 443 51544 SYN-ACK github.com
192.168.1.10 -> 1.1.1.1 UDP 53533 53 DNS query github.com
192.168.1.20 -> 192.168.1.1 ICMP - - echo-request gateway
192.168.1.15 -> 192.168.1.255 ARP - - who-has 192.168.1.1"""


def observe_packets(text: str = "") -> dict[str, Any]:
    """Parse simple packet/event lines into a beginner-friendly traffic view.

    This is intentionally a parser for pasted logs or demo data, not a packet
    sniffer. It never captures interfaces and never decrypts HTTPS.
    """
    source = text.strip() or DEMO_TRAFFIC
    packets = [_parse_line(line) for line in source.splitlines() if line.strip()]
    packets = [packet for packet in packets if packet]
    protocol_counts = Counter(str(packet["protocol"]) for packet in packets)
    flags = Counter(flag for packet in packets for flag in packet.get("flags", []))
    return {
        "mode": "log_or_demo",
        "description": "Lecture pedagogique de lignes de trafic fournies, sans capture active.",
        "packets": packets,
        "statistics": {
            "total": len(packets),
            "protocols": dict(protocol_counts),
            "tcp_flags": dict(flags),
        },
        "timeline": [
            {
                "source": packet["source_ip"],
                "type": packet["protocol"],
                "description": packet["summary"],
                "level": "info",
            }
            for packet in packets
        ],
        "limitations": [
            "Aucune interface reseau n'est capturee par cet outil.",
            "HTTPS n'est pas dechiffre et ne doit pas l'etre sans cle legitime.",
            "Les lignes non reconnues sont ignorees plutot que devinees.",
        ],
    }


def _parse_line(line: str) -> dict[str, Any]:
    parts = line.split()
    if len(parts) < 5:
        return {}
    if parts[1] in {"->", "=>"}:
        source_ip, destination_ip = parts[0], parts[2]
        protocol = parts[3].upper()
        source_port = parts[4] if len(parts) > 4 else "-"
        destination_port = parts[5] if len(parts) > 5 else "-"
        rest = parts[6:]
    else:
        match = re.match(
            r"(?P<src>\S+)\s+(?P<dst>\S+)\s+(?P<proto>TCP|UDP|DNS|HTTP|HTTPS|ICMP|ARP)\s*(?P<rest>.*)",
            line,
            re.IGNORECASE,
        )
        if not match:
            return {}
        source_ip = match.group("src")
        destination_ip = match.group("dst")
        protocol = match.group("proto").upper()
        rest = match.group("rest").split()
        source_port = rest[0] if rest else "-"
        destination_port = rest[1] if len(rest) > 1 else "-"
        rest = rest[2:]
    flags = [item.upper() for item in rest if item.upper() in {"SYN", "SYN-ACK", "ACK", "FIN", "RST"}]
    human_target = next((item for item in reversed(rest) if "." in item and not item.replace(".", "").isdigit()), destination_ip)
    summary = _summary(source_ip, destination_ip, protocol, source_port, destination_port, flags, human_target, rest)
    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "direction": f"{source_ip} -> {destination_ip}",
        "flags": flags,
        "summary": summary,
        "raw": line,
    }


def _summary(
    source_ip: str,
    destination_ip: str,
    protocol: str,
    source_port: str,
    destination_port: str,
    flags: list[str],
    human_target: str,
    rest: list[str],
) -> str:
    flag_text = f" {', '.join(flags)}" if flags else ""
    if protocol == "TCP":
        if "SYN" in flags:
            return f"{source_ip} -> {human_target}: TCP SYN, demande d'ouverture de connexion."
        if "SYN-ACK" in flags:
            return f"{source_ip} -> {destination_ip}: TCP SYN-ACK, reponse d'ouverture de connexion."
        return f"{source_ip} -> {destination_ip}: TCP{flag_text} {source_port}->{destination_port}."
    if protocol in {"DNS", "UDP"} and (destination_port == "53" or "DNS" in [item.upper() for item in rest]):
        return f"{source_ip} -> {human_target}: requete DNS observee."
    if protocol == "ICMP":
        return f"{source_ip} -> {destination_ip}: ICMP, test de joignabilite."
    if protocol == "ARP":
        return f"{source_ip}: ARP, recherche d'adresse sur le reseau local."
    if protocol in {"HTTP", "HTTPS"}:
        return f"{source_ip} -> {human_target}: {protocol}, echange web sans lecture du contenu chiffre."
    return f"{source_ip} -> {destination_ip}: {protocol}{flag_text}."

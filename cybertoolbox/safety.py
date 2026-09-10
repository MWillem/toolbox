from __future__ import annotations

import ipaddress
import socket


MAX_PORTS = 1024
MAX_HOSTS = 256


def resolve_authorized_target(target: str) -> list[str]:
    """Resolve a target and only return local or private IP addresses."""
    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Cible introuvable : {target}") from exc

    addresses = sorted({info[4][0] for info in infos})
    allowed = []
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_loopback or ip.is_private:
            allowed.append(address)

    if not allowed:
        raise ValueError(
            "Seules les cibles locales ou privées sont autorisées "
            "(localhost, 10/8, 172.16/12, 192.168/16)."
        )
    return allowed


def parse_ports(value: str) -> list[int]:
    """Parse comma-separated ports and inclusive ranges."""
    ports: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"Plage invalide : {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise ValueError("Les ports doivent être compris entre 1 et 65535.")
    if len(ports) > MAX_PORTS:
        raise ValueError(f"Un atelier est limité à {MAX_PORTS} ports.")
    return sorted(ports)


def parse_private_network(value: str) -> ipaddress.IPv4Network:
    """Validate a private IPv4 network small enough for an educational scan."""
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError("Réseau invalide. Exemple attendu : 192.168.1.0/24.") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("La découverte guidée prend actuellement en charge IPv4.")
    if not network.is_private:
        raise ValueError("Seuls les réseaux privés sont autorisés.")
    if network.num_addresses > MAX_HOSTS:
        raise ValueError(f"Le réseau est limité à {MAX_HOSTS} adresses (par exemple /24).")
    return network

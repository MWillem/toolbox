from __future__ import annotations

import json
import platform
import socket
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .labs.bluetooth_advanced import scan_bluetooth_devices
from .labs.network import discover_hosts
from .labs.wireless import local_device_identity, wifi_scan


USERNAME_SITES = {
    "GitHub": "https://github.com/{username}",
    "Twitter/X": "https://twitter.com/{username}",
    "Instagram": "https://www.instagram.com/{username}/",
    "Reddit": "https://www.reddit.com/user/{username}/",
    "Twitch": "https://www.twitch.tv/{username}",
}


def search_username_online(username: str) -> dict[str, Any]:
    """Vérifie passivement l'existence d'un pseudonyme sur cinq sites publics."""
    clean = username.strip()
    if not clean or len(clean) > 64:
        raise ValueError("Le username doit contenir entre 1 et 64 caractères.")
    encoded = quote(clean, safe="._-")
    found_sites = []
    checked_sites = []
    for site, template in USERNAME_SITES.items():
        url = template.format(username=encoded)
        status, exists, explanation = _head_exists(url)
        checked_sites.append(
            {
                "site": site,
                "url": url,
                "status": status,
                "exists": exists,
                "explanation": explanation,
            }
        )
        if exists:
            found_sites.append({"site": site, "url": url})
    return {
        "username": clean,
        "found_sites": found_sites,
        "total": len(found_sites),
        "checked_sites": checked_sites,
        "limitations": (
            "Un statut HTTP ne prouve pas que le compte appartient à une personne "
            "précise. Certains sites bloquent HEAD ou renvoient des pages génériques."
        ),
    }


def calculate_digital_shadow_score(
    device_profile: dict[str, Any],
) -> dict[str, Any]:
    """Calcule un score pédagogique d'exposition à partir d'un profil technique."""
    services = device_profile.get("services") or []
    open_ports = device_profile.get("open_ports") or services
    usernames = (
        device_profile.get("usernames")
        or device_profile.get("found_sites")
        or device_profile.get("online_accounts")
        or []
    )
    details = {
        "ports_over_three": 10 if len(open_ports) > 3 else 0,
        "identified_services": 10 if services else 0,
        "mac_found": 10 if _known(device_profile.get("mac")) else 0,
        "hostname_found": 10 if _known(device_profile.get("hostname")) else 0,
        "manufacturer_found": 10 if _known(device_profile.get("manufacturer")) else 0,
        "usernames_found": min(30, len(usernames) * 10),
        "ip_location_found": 10 if _has_location(device_profile) else 0,
    }
    score = min(100, sum(details.values()))
    risk_level = "low" if score < 35 else "medium" if score < 70 else "high"
    return {
        "score": score,
        "details": details,
        "risk_level": risk_level,
        "explanation": (
            "Ce score mesure la quantité d'informations techniques observables, "
            "pas la dangerosité d'une personne ni la présence d'une compromission."
        ),
    }


def profile_current_environment() -> dict[str, Any]:
    """Construit un profil de l'appareil courant et de son réseau local."""
    identity = local_device_identity()
    public = _public_ip_information()
    network = _local_network()
    network_devices: list[dict[str, str]] = []
    network_engine = "-"
    network_error = ""
    if network:
        try:
            network_devices, network_engine = discover_hosts(network)
        except (ValueError, OSError) as exc:
            network_error = str(exc)
    return {
        "public_ip": public.get("ip", ""),
        "location": {
            "city": public.get("city", ""),
            "region": public.get("region", ""),
            "country": public.get("country", ""),
            "loc": public.get("loc", ""),
            "organization": public.get("org", ""),
        },
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "identity": identity,
        "wifi_visible": wifi_scan(),
        "bluetooth_visible": scan_bluetooth_devices(),
        "local_network": network or "indisponible",
        "network_devices": network_devices,
        "network_engine": network_engine,
        "network_error": network_error,
        "limitations": [
            "L'IP publique et sa localisation approximative proviennent d'un service Internet.",
            "La géolocalisation IP peut correspondre à l'opérateur et non à la position réelle.",
            "Les appareils locaux peuvent ignorer les sondes ou être masqués par un pare-feu.",
        ],
    }


def display_watchdogs_profile(profile: dict[str, Any]) -> None:
    """Affiche un profil technique coloré inspiré d'une interface Watch Dogs."""
    score_data = profile.get("digital_shadow") or calculate_digital_shadow_score(profile)
    score = score_data.get("score", 0)
    risk = str(score_data.get("risk_level", "low")).upper()
    color = "\033[92m" if risk == "LOW" else "\033[93m" if risk == "MEDIUM" else "\033[91m"
    reset = "\033[0m"
    wifi = profile.get("wifi_visible", {})
    bluetooth = profile.get("bluetooth_visible", [])
    wifi_count = len(wifi.get("networks", [])) if isinstance(wifi, dict) else len(wifi)
    print("\033[95m╔══════════════════════════════════════════════╗\033[0m")
    print("\033[95m║          WATCHDOGS // ASSET PROFILE          ║\033[0m")
    print("\033[95m╚══════════════════════════════════════════════╝\033[0m")
    print(f"🛡  SCORE D'OMBRE : {color}{score:03d}/100 [{risk}]{reset}")
    print(f"🌐 IP PUBLIQUE    : {profile.get('public_ip') or profile.get('address', '-')}")
    print(f"📍 LOCALISATION   : {_location_label(profile)}")
    print(f"💻 HOSTNAME       : {profile.get('hostname', '-')}")
    print(f"⚙  SYSTÈME        : {profile.get('platform') or profile.get('device_type', '-')}")
    print(f"📶 WI-FI VISIBLES : {wifi_count}")
    print(f"ᛒ  BLUETOOTH      : {len(bluetooth)}")
    print(f"🔌 SERVICES       : {len(profile.get('services', []))}")
    print("\033[90mProfil technique indicatif, sans identification personnelle.\033[0m")


def _head_exists(url: str) -> tuple[int | None, bool, str]:
    request = Request(
        url,
        method="HEAD",
        headers={"User-Agent": "CyberToolbox/2.13 (+educational-osint)"},
    )
    try:
        with urlopen(request, timeout=6) as response:
            status = response.status
            return status, status < 400, "Réponse HTTP publique."
    except HTTPError as exc:
        if exc.code in {401, 403, 405, 429}:
            return exc.code, False, "Vérification bloquée ou non concluante."
        return exc.code, False, "Profil non trouvé selon le statut HTTP."
    except (URLError, TimeoutError, OSError) as exc:
        return None, False, f"Vérification impossible : {exc}"


def _public_ip_information() -> dict[str, Any]:
    request = Request(
        "https://ipinfo.io/json",
        headers={"User-Agent": "CyberToolbox/2.13"},
    )
    try:
        with urlopen(request, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8"))
            return payload if isinstance(payload, dict) else {}
    except (URLError, HTTPError, TimeoutError, OSError, json.JSONDecodeError):
        fallback = Request(
            "https://ifconfig.co/json",
            headers={
                "Accept": "application/json",
                "User-Agent": "CyberToolbox/2.13",
            },
        )
        try:
            with urlopen(fallback, timeout=8) as response:
                payload = json.loads(response.read().decode("utf-8"))
                if isinstance(payload, dict):
                    return {
                        "ip": payload.get("ip", ""),
                        "city": payload.get("city", ""),
                        "region": payload.get("region_name", ""),
                        "country": payload.get("country_iso", ""),
                        "loc": ",".join(
                            str(payload.get(key, ""))
                            for key in ("latitude", "longitude")
                        ),
                        "org": payload.get("asn_org", ""),
                    }
        except (URLError, HTTPError, TimeoutError, OSError, json.JSONDecodeError):
            return {}
    return {}


def _local_network() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 80))
        address = sock.getsockname()[0]
    except OSError:
        try:
            address = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            return ""
    finally:
        sock.close()
    parts = address.split(".")
    if len(parts) != 4 or address.startswith("127."):
        return ""
    return ".".join(parts[:3]) + ".0/24"


def _known(value: Any) -> bool:
    return bool(value and str(value).strip().lower() not in {"-", "inconnu", "unknown"})


def _has_location(profile: dict[str, Any]) -> bool:
    location = profile.get("location")
    if isinstance(location, dict):
        return any(_known(value) for value in location.values())
    return _known(location) or _known(profile.get("ip_location"))


def _location_label(profile: dict[str, Any]) -> str:
    location = profile.get("location", {})
    if isinstance(location, dict):
        values = [
            str(location.get(key, "")).strip()
            for key in ("city", "region", "country")
            if str(location.get(key, "")).strip()
        ]
        return ", ".join(values) or str(location.get("loc") or "-")
    return str(location or profile.get("ip_location") or "-")

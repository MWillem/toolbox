from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
from typing import Any


def wifi_scan() -> dict[str, object]:
    """Return visible Wi-Fi networks using the safest available system API."""
    system = platform.system()
    if shutil.which("termux-wifi-scaninfo"):
        result = _run(["termux-wifi-scaninfo"], timeout=30)
        networks = _parse_termux_scan(result["output"]) if result["available"] else []
        return _scan_result("Termux:API", networks, result)
    if system == "Windows":
        result = _run(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=30)
        networks = _parse_netsh_scan(result["output"]) if result["available"] else []
        connected_result = _run(["netsh", "wlan", "show", "interfaces"], timeout=15)
        connected = (
            _parse_netsh_interface(connected_result["output"])
            if connected_result["available"]
            else None
        )
        if result["available"]:
            if connected:
                matched = False
                for network in networks:
                    same_bssid = bool(connected["bssid"]) and (
                        str(network["bssid"]).lower() == str(connected["bssid"]).lower()
                    )
                    same_ssid = network["ssid"] == connected["ssid"]
                    if same_bssid or same_ssid:
                        network["connected"] = True
                        matched = True
                if not matched:
                    networks.append(connected)
            return _scan_result("netsh", networks, result)
        limitations = _wifi_limitations()
        error = str(result.get("error") or result.get("output") or "")
        if "localisation" in error.lower() or "location" in error.lower():
            limitations.insert(
                0,
                "Windows bloque le scan complet : activez Paramètres > "
                "Confidentialité et sécurité > Localisation, puis autorisez les applications de bureau.",
            )
        if "élévation" in error.lower() or "elevation" in error.lower():
            limitations.insert(
                1,
                "Windows demande une élévation pour cette commande : relancez le terminal "
                "en administrateur uniquement pour votre démonstration autorisée.",
            )
        return {
            "available": bool(connected),
            "scan_complete": False,
            "engine": "netsh",
            "description": (
                "Le scan des réseaux voisins a été refusé par Windows. "
                "Le réseau connecté est affiché comme information de secours."
            ),
            "networks": [connected] if connected else [],
            "output": error,
            "limitations": limitations,
        }
    if shutil.which("nmcli"):
        result = _run(
            [
                "nmcli",
                "--terse",
                "--escape",
                "yes",
                "--fields",
                "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY",
                "device",
                "wifi",
                "list",
                "--rescan",
                "yes",
            ],
            timeout=30,
        )
        networks = _parse_nmcli_scan(result["output"]) if result["available"] else []
        return _scan_result("nmcli", networks, result)
    return {
        "available": False,
        "engine": "-",
        "description": "Aucune API de scan Wi-Fi compatible détectée.",
        "networks": [],
        "output": "",
        "limitations": _wifi_limitations(),
    }


def wifi_inventory() -> dict[str, object]:
    """Compatibility wrapper used by the existing CLI."""
    scan = wifi_scan()
    lines = [
        (
            f"{item['ssid'] or '<masqué>'} | {item['bssid'] or '?'} | "
            f"canal {item['channel'] or '?'} | signal {item['signal'] or '?'} | "
            f"{item['security'] or 'inconnu'}"
        )
        for item in scan["networks"]
    ]
    return {
        "available": scan["available"],
        "engine": scan["engine"],
        "description": scan["description"],
        "output": "\n".join(lines) or scan.get("output", ""),
        "items": scan["networks"],
        "limitations": scan["limitations"],
    }


def bluetooth_inventory() -> dict[str, object]:
    """List devices already exposed by the operating system, without pairing."""
    system = platform.system()
    if system == "Windows":
        result = _run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-PnpDevice -Class Bluetooth | "
                    "Select-Object Status,FriendlyName,InstanceId | ConvertTo-Json"
                ),
            ]
        )
        items = _parse_windows_bluetooth(result["output"]) if result["available"] else []
        return _bluetooth_result("Get-PnpDevice", items, result)
    if shutil.which("bluetoothctl"):
        result = _run(["bluetoothctl", "devices"])
        items = _parse_bluetoothctl(result["output"]) if result["available"] else []
        return _bluetooth_result("bluetoothctl", items, result)
    return {
        "available": False,
        "engine": "-",
        "description": "Aucune API Bluetooth compatible détectée.",
        "output": "",
        "items": [],
        "limitations": [
            "Bluetooth désactivé, non autorisé ou non pris en charge par cet environnement.",
            "Un appareil non appairé ou non visible peut ne pas apparaître.",
        ],
    }


def mobile_operator_info() -> dict[str, object]:
    """Read non-sensitive carrier information from the current Android device."""
    command = "termux-telephony-deviceinfo"
    if not shutil.which(command):
        return {
            "available": False,
            "scope": "appareil courant uniquement",
            "description": (
                "Informations téléphoniques indisponibles. Cette fonction nécessite "
                "Termux:API sur le téléphone qui exécute la toolbox."
            ),
            "operator": {},
            "limitations": [
                "L'opérateur mobile d'un téléphone tiers ne peut pas être déduit du Wi-Fi.",
                "Android peut exiger l'autorisation Téléphone pour Termux:API.",
            ],
        }
    result = _run([command], timeout=20)
    try:
        payload = json.loads(str(result["output"])) if result["available"] else {}
    except json.JSONDecodeError:
        payload = {}
    allowed = (
        "network_operator_name",
        "network_operator",
        "network_country_iso",
        "network_type",
        "network_roaming",
        "sim_operator_name",
        "sim_operator",
        "sim_country_iso",
        "sim_state",
        "phone_count",
        "phone_type",
        "data_enabled",
        "data_state",
    )
    operator = {
        key: payload[key]
        for key in allowed
        if isinstance(payload, dict) and payload.get(key) not in {"", None}
    }
    return {
        "available": bool(result["available"] and operator),
        "scope": "appareil courant uniquement",
        "description": (
            "Opérateur et état radio exposés par Android pour ce téléphone. "
            "Les identifiants SIM, abonné et appareil sont filtrés."
        ),
        "operator": operator,
        "limitations": [
            "Le nom peut représenter le réseau actuellement utilisé ou l'opérateur de la SIM.",
            "Itinérance, double SIM et opérateurs virtuels peuvent produire plusieurs notions d'opérateur.",
            "Aucune information n'est collectée sur un téléphone tiers.",
        ],
    }


def wireless_diagnostics() -> dict[str, object]:
    system = platform.system()
    tools = {
        name: bool(shutil.which(name))
        for name in (
            "netsh",
            "nmcli",
            "iw",
            "iwlist",
            "bluetoothctl",
            "termux-wifi-scaninfo",
            "termux-wifi-connectioninfo",
            "termux-telephony-deviceinfo",
        )
    }
    return {
        "platform": system,
        "tools": tools,
        "wifi_scan_available": any(
            tools[name] for name in ("netsh", "nmcli", "termux-wifi-scaninfo")
        ),
        "bluetooth_inventory_available": tools["bluetoothctl"] or system == "Windows",
        "mobile_operator_available": tools["termux-telephony-deviceinfo"],
        "monitor_mode": (
            "Non piloté par la toolbox. Il dépend de Linux, du pilote, des droits "
            "et souvent d'un adaptateur externe compatible."
        ),
        "termux_help": (
            "Dans Termux : installer l'application Termux:API, puis exécuter "
            "`pkg install termux-api` et accorder les permissions Android."
        ),
    }


def local_device_identity() -> dict[str, str]:
    identity = {
        "hostname": platform.node() or "inconnu",
        "system": platform.system() or "inconnu",
        "release": platform.release() or "inconnu",
        "machine": platform.machine() or "inconnu",
        "model": "",
        "manufacturer": "",
    }
    if "com.termux" in os.environ.get("PREFIX", "") or platform.system() == "Linux":
        for key, property_name in (
            ("model", "ro.product.model"),
            ("manufacturer", "ro.product.manufacturer"),
        ):
            if not shutil.which("getprop"):
                break
            result = _run(["getprop", property_name], timeout=5)
            if result["available"]:
                identity[key] = str(result["output"]).strip()
    return identity


def wifi_security_lesson(security: str) -> list[str]:
    value = security.upper()
    if not value or value in {"--", "OPEN", "NONE"}:
        return [
            "Réseau ouvert : le trafic radio n'est pas protégé par une clé Wi-Fi.",
            "Privilégier HTTPS/VPN et éviter les données sensibles.",
        ]
    if "WEP" in value:
        return [
            "WEP est obsolète et ne doit plus être utilisé.",
            "Migrer vers WPA2-AES ou WPA3.",
        ]
    if "WPA3" in value:
        return [
            "WPA3 améliore la résistance aux attaques hors ligne.",
            "Un mot de passe long et les mises à jour restent nécessaires.",
        ]
    if "WPA2" in value:
        return [
            "WPA2 reste courant ; sa résistance dépend fortement du mot de passe.",
            "Désactiver WPS et choisir une phrase longue et unique.",
        ]
    return [
        "La sécurité annoncée doit être confirmée dans la configuration du point d'accès.",
        "Éviter les protocoles anciens et désactiver WPS lorsqu'il n'est pas nécessaire.",
    ]


def _scan_result(
    engine: str,
    networks: list[dict[str, object]],
    process: dict[str, object],
) -> dict[str, object]:
    return {
        "available": bool(process["available"]),
        "scan_complete": bool(process["available"]),
        "engine": engine,
        "description": "Réseaux Wi-Fi visibles exposés par le système.",
        "networks": sorted(
            networks,
            key=lambda item: int(item.get("signal") or -100),
            reverse=True,
        ),
        "output": process["output"],
        "limitations": _wifi_limitations(),
    }


def _bluetooth_result(
    engine: str,
    items: list[dict[str, str]],
    process: dict[str, object],
) -> dict[str, object]:
    return {
        "available": bool(process["available"]),
        "engine": engine,
        "description": "Appareils Bluetooth connus ou visibles selon le système.",
        "output": process["output"],
        "items": items,
        "limitations": [
            "Le nom Bluetooth est déclaré par l'appareil et peut être modifié.",
            "L'absence d'un appareil ne prouve pas son absence physique.",
            "Aucun appairage ni connexion n'est réalisé.",
        ],
    }


def _wifi_limitations() -> list[str]:
    return [
        "Le scan est une observation radio, pas une autorisation de tester un réseau.",
        "Android peut limiter la fréquence des scans et exiger localisation/appareils à proximité.",
        "Un SSID ou BSSID ne permet pas d'identifier avec certitude une personne.",
        "Le Wi-Fi interne d'un téléphone ne fournit généralement pas le mode monitor à Termux.",
    ]


def _run(command: list[str], timeout: int = 20) -> dict[str, object]:
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "output": "", "error": str(exc)}
    output = process.stdout.strip() or process.stderr.strip()
    return {
        "available": process.returncode == 0,
        "output": output,
        "error": "" if process.returncode == 0 else output,
    }


def _parse_termux_scan(output: str) -> list[dict[str, object]]:
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return []
    networks = []
    for item in payload if isinstance(payload, list) else []:
        frequency = int(item.get("frequency_mhz") or item.get("frequency") or 0)
        networks.append(
            {
                "ssid": str(item.get("ssid") or ""),
                "bssid": str(item.get("bssid") or ""),
                "channel": _frequency_to_channel(frequency),
                "frequency": frequency or "",
                "signal": int(item.get("rssi") or -100),
                "security": str(item.get("capabilities") or "inconnu"),
            }
        )
    return networks


def _parse_nmcli_scan(output: str) -> list[dict[str, object]]:
    networks = []
    for line in output.splitlines():
        fields = _split_nmcli(line)
        if len(fields) < 6:
            continue
        ssid, bssid, channel, frequency, signal, security = fields[:6]
        networks.append(
            {
                "ssid": ssid,
                "bssid": bssid,
                "channel": channel,
                "frequency": frequency,
                "signal": _signal_percent_to_dbm(signal),
                "security": security or "ouvert",
            }
        )
    return networks


def _split_nmcli(line: str) -> list[str]:
    fields: list[str] = []
    current = []
    escaped = False
    for character in line:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    fields.append("".join(current))
    return fields


def _parse_netsh_scan(output: str) -> list[dict[str, object]]:
    networks: list[dict[str, object]] = []
    current_ssid = ""
    current_security = ""
    current: dict[str, object] | None = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        ssid = re.match(r"SSID\s+\d+\s*:\s*(.*)", line, re.IGNORECASE)
        if ssid:
            current_ssid = ssid.group(1).strip()
            current_security = ""
            continue
        auth = re.match(r"(?:Authentication|Authentification)\s*:\s*(.*)", line, re.IGNORECASE)
        if auth:
            current_security = auth.group(1).strip()
            continue
        bssid = re.match(r"BSSID\s+\d+\s*:\s*(.*)", line, re.IGNORECASE)
        if bssid:
            current = {
                "ssid": current_ssid,
                "bssid": bssid.group(1).strip(),
                "channel": "",
                "frequency": "",
                "signal": -100,
                "security": current_security or "inconnu",
            }
            networks.append(current)
            continue
        if current is None:
            continue
        signal = re.match(r"Signal\s*:\s*(\d+)%", line, re.IGNORECASE)
        if signal:
            current["signal"] = _signal_percent_to_dbm(signal.group(1))
        channel = re.match(r"(?:Channel|Canal)\s*:\s*(\d+)", line, re.IGNORECASE)
        if channel:
            current["channel"] = channel.group(1)
    return networks


def _parse_netsh_interface(output: str) -> dict[str, object] | None:
    values: dict[str, str] = {}
    for raw_line in output.splitlines():
        match = re.match(r"\s*([^:]+?)\s*:\s*(.*)", raw_line)
        if match:
            values[match.group(1).strip().lower()] = match.group(2).strip()
    ssid = values.get("ssid", "")
    if not ssid:
        return None
    signal = values.get("signal", "").rstrip("%")
    return {
        "ssid": ssid,
        "bssid": values.get("bssid", ""),
        "channel": values.get("canal", values.get("channel", "")),
        "frequency": "",
        "signal": _signal_percent_to_dbm(signal),
        "security": values.get(
            "authentification",
            values.get("authentication", "inconnu"),
        ),
        "connected": True,
    }


def _parse_windows_bluetooth(output: str) -> list[dict[str, str]]:
    try:
        payload: Any = json.loads(output)
    except json.JSONDecodeError:
        return []
    rows = payload if isinstance(payload, list) else [payload]
    return [
        {
            "name": str(item.get("FriendlyName") or "Inconnu"),
            "status": str(item.get("Status") or ""),
            "identifier": str(item.get("InstanceId") or ""),
        }
        for item in rows
        if isinstance(item, dict)
    ]


def _parse_bluetoothctl(output: str) -> list[dict[str, str]]:
    items = []
    for line in output.splitlines():
        match = re.match(r"Device\s+([0-9A-F:]{17})\s+(.+)", line, re.IGNORECASE)
        if match:
            items.append(
                {"identifier": match.group(1).upper(), "name": match.group(2), "status": "connu"}
            )
    return items


def _signal_percent_to_dbm(value: str) -> int:
    try:
        percent = max(0, min(100, int(value)))
    except ValueError:
        return -100
    return round(percent / 2 - 100)


def _frequency_to_channel(frequency: int) -> int | str:
    if 2412 <= frequency <= 2472:
        return (frequency - 2407) // 5
    if frequency == 2484:
        return 14
    if 5000 <= frequency <= 5895:
        return (frequency - 5000) // 5
    if 5955 <= frequency <= 7115:
        return (frequency - 5950) // 5
    return ""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from typing import Any


OUI_MANUFACTURERS = {
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0A:27": "Apple",
    "00:0A:95": "Apple",
    "00:0D:93": "Apple",
    "00:16:CB": "Apple",
    "00:17:F2": "Apple",
    "00:19:E3": "Apple",
    "00:1B:63": "Apple",
    "00:1C:B3": "Apple",
    "00:1D:4F": "Apple",
    "00:1E:C2": "Apple",
    "00:1F:5B": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:23:DF": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4B": "Apple",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "04:1B:94": "Apple",
    "04:26:65": "Apple",
    "04:52:F3": "Apple",
    "04:54:53": "Apple",
    "04:69:F8": "Apple",
    "08:00:07": "Apple",
    "08:70:45": "Apple",
    "10:40:F3": "Apple",
    "14:10:9F": "Apple",
    "18:34:51": "Apple",
    "1C:AB:A7": "Apple",
    "20:3C:AE": "Apple",
    "28:CF:DA": "Apple",
    "2C:B4:3A": "Apple",
    "34:15:9E": "Apple",
    "38:C9:86": "Apple",
    "3C:07:54": "Apple",
    "40:30:04": "Apple",
    "44:2A:60": "Apple",
    "48:A1:95": "Apple",
    "4C:57:CA": "Apple",
    "50:EA:D6": "Apple",
    "54:26:96": "Apple",
    "58:55:CA": "Apple",
    "5C:95:AE": "Apple",
    "60:03:08": "Apple",
    "60:69:44": "Apple",
    "64:A3:CB": "Apple",
    "68:5B:35": "Apple",
    "6C:40:08": "Apple",
    "70:56:81": "Apple",
    "74:E2:F5": "Apple",
    "78:31:C1": "Apple",
    "7C:C3:A1": "Apple",
    "80:E6:50": "Apple",
    "84:FC:FE": "Apple",
    "88:63:DF": "Apple",
    "8C:85:90": "Apple",
    "90:72:40": "Apple",
    "94:E9:6A": "Apple",
    "98:03:D8": "Apple",
    "9C:20:7B": "Apple",
    "A0:99:9B": "Apple",
    "A4:5E:60": "Apple",
    "A8:66:7F": "Apple",
    "AC:BC:32": "Apple",
    "B0:34:95": "Apple",
    "B4:F0:AB": "Apple",
    "B8:17:C2": "Apple",
    "BC:3B:AF": "Apple",
    "C0:CE:CD": "Apple",
    "C8:2A:14": "Apple",
    "CC:08:8D": "Apple",
    "D0:03:4B": "Apple",
    "D4:9A:20": "Apple",
    "D8:30:62": "Apple",
    "DC:2B:2A": "Apple",
    "E0:B5:2D": "Apple",
    "E4:CE:8F": "Apple",
    "E8:80:2E": "Apple",
    "EC:35:86": "Apple",
    "F0:18:98": "Apple",
    "F4:5C:89": "Apple",
    "F8:1E:DF": "Apple",
    "FC:E9:98": "Apple",
    "00:07:AB": "Samsung",
    "00:12:FB": "Samsung",
    "08:37:3D": "Samsung",
    "10:D5:42": "Samsung",
    "14:49:E0": "Samsung",
    "18:3A:2D": "Samsung",
    "1C:62:B8": "Samsung",
    "20:13:E0": "Samsung",
    "24:4B:81": "Samsung",
    "28:98:7B": "Samsung",
    "30:07:4D": "Samsung",
    "34:23:BA": "Samsung",
    "38:01:95": "Samsung",
    "3C:5A:B4": "Google",
    "54:60:09": "Google",
    "94:EB:2C": "Google",
    "F4:F5:D8": "Google",
    "00:1B:DC": "Intel",
    "00:1E:64": "Intel",
    "3C:97:0E": "Intel",
    "5C:51:4F": "Intel",
    "68:05:CA": "Intel",
    "84:3A:4B": "Intel",
    "A4:34:D9": "Intel",
    "DC:53:60": "Intel",
    "00:1A:7D": "Cambridge Silicon Radio",
    "00:1B:10": "Shenzhen Tenda",
    "00:1E:3A": "Nokia",
    "00:24:1C": "Nokia",
    "00:26:5A": "D-Link",
    "04:18:0F": "Huawei",
    "0C:96:E6": "Cloud Network Technology",
    "10:2A:B3": "Xiaomi",
    "18:59:36": "Xiaomi",
    "28:6C:07": "Xiaomi",
    "34:80:B3": "Xiaomi",
    "50:64:2B": "Xiaomi",
    "64:09:80": "Xiaomi",
    "7C:49:EB": "Xiaomi",
    "9C:99:A0": "Xiaomi",
    "AC:C1:EE": "Xiaomi",
    "F8:A4:5F": "Xiaomi",
    "18:65:90": "TP-Link",
    "50:C7:BF": "TP-Link",
    "60:E3:27": "TP-Link",
    "A0:F3:C1": "TP-Link",
    "B0:BE:76": "TP-Link",
    "D8:0D:17": "TP-Link",
    "E8:48:B8": "TP-Link",
    "00:04:20": "Slim Devices / Logitech",
    "00:1F:20": "Logitech",
    "88:C6:26": "Logitech",
    "C0:28:8D": "Logitech",
    "00:0E:6D": "Murata",
    "00:1A:11": "Google",
    "00:17:88": "Philips Lighting",
    "00:1D:A5": "RIM / BlackBerry",
    "00:22:68": "Hon Hai / Foxconn",
    "00:24:BE": "Sony",
    "00:25:E7": "Sony Ericsson",
    "04:5D:4B": "Sony",
    "28:0D:FC": "Sony",
    "AC:9B:0A": "Sony",
    "00:26:BB": "Apple",
    "08:3E:8E": "Hon Hai / Foxconn",
    "20:02:AF": "Murata",
    "40:4E:36": "HTC",
    "64:BC:0C": "LG Electronics",
    "88:9F:6F": "Sony",
    "A8:16:B2": "LG Electronics",
    "B8:5A:73": "Samsung",
    "CC:FA:00": "LG Electronics",
    "F8:CF:C5": "Motorola",
}

OUI_MANUFACTURERS.update(
    {
        "00:00:0C": "Cisco",
        "00:01:42": "Cisco",
        "00:14:22": "Dell",
        "00:1A:A0": "Dell",
        "00:01:E6": "Hewlett-Packard",
        "00:1B:78": "Hewlett-Packard",
        "00:06:1B": "Lenovo",
        "00:21:CC": "Lenovo",
        "00:1A:92": "ASUSTek",
        "00:22:15": "ASUSTek",
        "00:1C:26": "Hon Hai / Acer",
        "00:50:F2": "Microsoft",
        "28:18:78": "Microsoft",
        "00:FC:8B": "Amazon",
        "44:65:0D": "Amazon",
        "00:09:BF": "Nintendo",
        "00:1F:32": "Nintendo",
        "B8:27:EB": "Raspberry Pi Foundation",
        "DC:A6:32": "Raspberry Pi Trading",
        "24:0A:C4": "Espressif",
        "30:AE:A4": "Espressif",
        "00:10:18": "Broadcom",
        "00:1A:F7": "Broadcom",
        "00:03:7F": "Qualcomm",
        "00:0A:F5": "Airgo / Qualcomm",
        "00:0C:8A": "Bose",
        "04:52:C7": "Bose",
        "00:06:F5": "Alps Alpine",
        "00:07:80": "Bluegiga",
        "00:0B:CE": "Free2move",
        "00:0D:18": "Mega-Trend",
        "00:0E:0C": "Intelbras",
        "00:0F:DE": "Sony Ericsson",
        "00:11:67": "Integrated System Solution",
        "00:12:1C": "PARROT",
        "00:13:7A": "Netgear",
        "00:14:6C": "Netgear",
        "00:15:6D": "Ubiquiti",
        "00:27:22": "Ubiquiti",
        "00:1A:1E": "Aruba Networks",
        "00:0B:86": "Aruba Networks",
        "00:05:85": "Juniper Networks",
        "00:10:DB": "Juniper Networks",
        "00:09:0F": "Fortinet",
        "00:1B:17": "Palo Alto Networks",
        "00:0C:29": "VMware",
        "00:50:56": "VMware",
        "00:00:AA": "Xerox",
        "00:80:77": "Brother Industries",
        "00:00:85": "Canon",
        "00:00:48": "Epson",
        "00:04:00": "Lexmark",
        "00:07:4D": "Zebra Technologies",
        "00:00:0E": "Fujitsu",
        "00:00:39": "Toshiba",
        "00:00:E8": "Accton",
        "00:01:24": "Acer",
        "00:01:6C": "Foxconn",
        "00:01:80": "ARRIS",
        "00:01:5C": "Cadant / ARRIS",
        "00:1D:7E": "Cisco-Linksys",
        "00:18:4D": "Netgear",
        "00:1E:58": "D-Link",
        "00:05:5D": "D-Link",
        "00:0F:B5": "Netgear",
        "00:1F:33": "Netgear",
        "00:23:69": "Cisco-Linksys",
        "00:25:9C": "Cisco-Linksys",
        "00:17:9A": "D-Link",
        "00:24:01": "D-Link",
        "00:1C:F0": "D-Link",
        "00:1E:E5": "Cisco-Linksys",
        "00:21:29": "Cisco-Linksys",
        "00:22:6B": "Cisco-Linksys",
        "00:23:54": "Cisco-Linksys",
        "00:26:5A": "D-Link",
        "00:0D:88": "D-Link",
        "00:11:95": "D-Link",
        "00:13:46": "D-Link",
        "00:15:E9": "D-Link",
        "00:17:9A": "D-Link",
        "00:19:5B": "D-Link",
        "00:1B:11": "D-Link",
        "00:21:91": "D-Link",
        "00:22:B0": "D-Link",
        "00:24:01": "D-Link",
        "00:26:5A": "D-Link",
        "00:18:E7": "Cameo Communications",
        "00:1D:0F": "TP-Link",
        "00:21:27": "TP-Link",
        "00:23:CD": "TP-Link",
        "00:25:86": "TP-Link",
        "00:27:19": "TP-Link",
        "00:1B:2F": "Netgear",
        "00:1E:2A": "Netgear",
        "00:22:3F": "Netgear",
        "00:24:B2": "Netgear",
        "00:26:F2": "Netgear",
        "00:1F:C6": "ASUSTek",
        "00:22:15": "ASUSTek",
        "00:23:54": "ASUSTek",
        "00:24:8C": "ASUSTek",
        "00:26:18": "ASUSTek",
        "00:1D:60": "ASUSTek",
        "00:1E:8C": "ASUSTek",
        "00:1A:92": "ASUSTek",
        "00:11:D8": "ASUSTek",
        "00:13:D4": "ASUSTek",
        "00:15:F2": "ASUSTek",
        "00:17:31": "ASUSTek",
        "00:18:F3": "ASUSTek",
        "00:1B:FC": "ASUSTek",
        "00:1D:60": "ASUSTek",
        "00:1E:8C": "ASUSTek",
        "00:1F:C6": "ASUSTek",
        "00:22:15": "ASUSTek",
        "00:23:54": "ASUSTek",
        "00:24:8C": "ASUSTek",
        "00:26:18": "ASUSTek",
        "00:04:20": "Sonos / Slim Devices",
        "00:0E:58": "Sonos",
        "34:7E:5C": "Sonos",
        "00:0D:4B": "Roku",
        "B0:A7:37": "Roku",
        "00:17:88": "Signify / Philips Hue",
        "00:0B:57": "Silicon Laboratories",
        "00:0B:6B": "Wistron NeWeb",
        "00:0D:4B": "Roku",
        "00:16:38": "TECNO Mobile",
        "00:1A:8A": "Samsung Techwin",
        "00:1C:43": "Samsung",
        "00:21:19": "Samsung",
        "00:23:39": "Samsung",
        "00:26:37": "Samsung",
        "08:EE:8B": "Samsung",
        "10:1D:C0": "Samsung",
        "14:89:FD": "Samsung",
        "18:46:17": "Samsung",
        "1C:5A:3E": "Samsung",
        "20:64:32": "Samsung",
        "24:4B:81": "Samsung",
        "28:98:7B": "Samsung",
        "2C:AE:2B": "Samsung",
        "30:07:4D": "Samsung",
        "34:23:BA": "Samsung",
        "38:01:95": "Samsung",
        "3C:5A:B4": "Google",
        "40:0E:85": "Samsung",
        "44:4E:1A": "Samsung",
        "48:44:F7": "Samsung",
        "4C:3C:16": "Samsung",
        "50:01:BB": "Samsung",
        "54:40:AD": "Samsung",
        "58:C3:8B": "Samsung",
        "5C:0A:5B": "Samsung",
        "60:6B:BD": "Samsung",
        "64:B3:10": "Samsung",
        "68:48:98": "Samsung",
        "6C:2F:2C": "Samsung",
        "70:F9:27": "Samsung",
        "74:45:8A": "Samsung",
        "78:1F:DB": "Samsung",
        "7C:61:93": "HTC",
        "80:18:A7": "Samsung",
        "84:25:DB": "Samsung",
        "88:32:9B": "Samsung",
        "8C:77:12": "Samsung",
        "90:18:7C": "Samsung",
        "94:35:0A": "Samsung",
        "98:52:B1": "Samsung",
        "9C:02:98": "Samsung",
        "A0:0B:BA": "Samsung",
        "A4:EB:D3": "Samsung",
        "A8:06:00": "Samsung",
        "AC:36:13": "Samsung",
        "B0:72:BF": "Samsung",
        "B4:07:F9": "Samsung",
        "B8:5A:73": "Samsung",
        "BC:47:60": "Samsung",
        "C0:BD:D1": "Samsung",
        "C4:73:1E": "Samsung",
        "C8:BA:94": "Samsung",
        "CC:07:AB": "Samsung",
        "D0:22:BE": "Samsung",
        "D4:E8:B2": "Samsung",
        "D8:57:EF": "Samsung",
        "DC:66:72": "Samsung",
        "E0:99:71": "Samsung",
        "E4:7C:F9": "Samsung",
        "E8:50:8B": "Samsung",
        "EC:1F:72": "Samsung",
        "F0:25:B7": "Samsung",
        "F4:09:D8": "Samsung",
        "F8:D0:BD": "Samsung",
        "FC:A1:3E": "Samsung",
    }
)


def scan_bluetooth_devices(timeout: int = 10) -> list[dict[str, Any]]:
    """Scanne les appareils Bluetooth classiques visibles sans les appairer."""
    duration = max(1, min(int(timeout), 60))
    if shutil.which("bluetoothctl"):
        _run(["bluetoothctl", "--timeout", str(duration), "scan", "on"], duration + 3)
        result = _run(["bluetoothctl", "devices"], 10)
        return _parse_bluetoothctl_devices(result["output"])
    if shutil.which("hcitool"):
        result = _run(["hcitool", "scan"], duration + 3)
        return _parse_hcitool_devices(result["output"])
    return []


def scan_ble_devices(timeout: int = 10) -> list[dict[str, Any]]:
    """Scanne les annonces BLE exposées par les outils Linux disponibles."""
    duration = max(1, min(int(timeout), 60))
    if shutil.which("bluetoothctl"):
        _run(
            ["bluetoothctl", "--timeout", str(duration), "scan", "on"],
            duration + 3,
        )
        devices = _parse_bluetoothctl_devices(
            _run(["bluetoothctl", "devices"], 10)["output"]
        )
        return [
            {
                "name": item["name"],
                "mac": item["mac"],
                "rssi": item["rssi"],
                "services_uuids": item["services"],
            }
            for item in devices
        ]
    if shutil.which("hcitool"):
        result = _run(["hcitool", "lescan", "--duplicates"], duration)
        devices = _parse_hcitool_devices(result["output"])
        return [
            {
                "name": item["name"],
                "mac": item["mac"],
                "rssi": "",
                "services_uuids": [],
            }
            for item in devices
        ]
    return []


def lookup_manufacturer(mac: str) -> str:
    """Retourne le fabricant probable associé au préfixe OUI d'une adresse MAC."""
    normalized = _normalize_mac(mac)
    if not normalized:
        return "Fabricant inconnu"
    return OUI_MANUFACTURERS.get(normalized[:8], "Fabricant inconnu")


def profile_bluetooth_device(mac: str) -> dict[str, Any]:
    """Construit un profil Bluetooth technique à partir des données locales."""
    normalized = _normalize_mac(mac)
    if not normalized:
        raise ValueError("Adresse MAC Bluetooth invalide.")
    info = ""
    if shutil.which("bluetoothctl"):
        info = _run(["bluetoothctl", "info", normalized], 15)["output"]
    parsed = _parse_bluetooth_info(info)
    name = parsed.get("name", "Inconnu")
    services = parsed.get("services", [])
    return {
        "mac": normalized,
        "name": name,
        "manufacturer": lookup_manufacturer(normalized),
        "device_type": _infer_device_type(name, services, parsed.get("class", "")),
        "services": services,
        "device_class": parsed.get("class", ""),
        "rssi": parsed.get("rssi", ""),
        "paired": parsed.get("paired", "inconnu"),
        "connected": parsed.get("connected", "inconnu"),
        "limitations": (
            "Le nom, la classe et la MAC peuvent être absents, modifiés ou "
            "aléatoires. Ce profil ne permet pas d'identifier une personne."
        ),
    }


def bt_security_lesson() -> str:
    """Explique les risques Bluetooth et les mesures de réduction d'exposition."""
    return (
        "Bluetooth expose des noms, services et parfois une adresse stable. Les "
        "risques incluent appairage non désiré, services anciens, spoofing et "
        "suivi lorsque l'adresse ne change pas. BlueBorne désigne une famille de "
        "vulnérabilités historiques corrigées par les mises à jour. Désactivez "
        "le mode visible hors besoin, refusez les demandes inattendues, supprimez "
        "les anciens appairages et maintenez téléphone, casque et ordinateur à jour."
    )


def bluetooth_support() -> dict[str, Any]:
    """Décrit les capacités Bluetooth réellement disponibles sur la plateforme."""
    termux = "com.termux" in os.environ.get("PREFIX", "")
    tools = {
        name: bool(shutil.which(name))
        for name in ("bluetoothctl", "hcitool", "gatttool")
    }
    explanation = ""
    if termux and not any(tools.values()):
        explanation = (
            "Termux:API n'expose pas de commande générique de scan Bluetooth. "
            "Android limite cette fonction ; utilisez les réglages système ou "
            "un environnement Linux avec adaptateur compatible."
        )
    elif platform.system() in {"Windows", "Darwin"} and not any(tools.values()):
        explanation = (
            "Le scan actif avancé n'est pas piloté sans API ou outil externe. "
            "L'inventaire système simple reste disponible dans wireless.py."
        )
    return {"platform": platform.system(), "tools": tools, "explanation": explanation}


def _run(command: list[str], timeout: int) -> dict[str, Any]:
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return {
            "success": process.returncode == 0,
            "output": process.stdout.strip() or process.stderr.strip(),
        }
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or exc.stderr or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return {"success": True, "output": str(output)}
    except FileNotFoundError as exc:
        return {"success": False, "output": str(exc)}


def _parse_bluetoothctl_devices(output: str) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in output.splitlines():
        found = re.search(r"Device\s+([0-9A-F:]{17})\s*(.*)", line, re.IGNORECASE)
        if not found:
            continue
        mac = found.group(1).upper()
        if mac in seen:
            continue
        seen.add(mac)
        devices.append(
            {
                "name": found.group(2).strip() or "Inconnu",
                "mac": mac,
                "rssi": "",
                "services": [],
                "device_class": "",
            }
        )
    return devices


def _parse_hcitool_devices(output: str) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in output.splitlines():
        found = re.search(r"([0-9A-F:]{17})\s+(.+)", line, re.IGNORECASE)
        if not found:
            continue
        mac = found.group(1).upper()
        if mac in seen:
            continue
        seen.add(mac)
        devices.append(
            {
                "name": found.group(2).strip() or "Inconnu",
                "mac": mac,
                "rssi": "",
                "services": [],
                "device_class": "",
            }
        )
    return devices


def _parse_bluetooth_info(output: str) -> dict[str, Any]:
    result: dict[str, Any] = {"services": []}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        normalized = key.lower()
        if normalized in {"name", "alias"} and "name" not in result:
            result["name"] = value
        elif normalized == "class":
            result["class"] = value
        elif normalized == "rssi":
            result["rssi"] = value
        elif normalized == "paired":
            result["paired"] = value
        elif normalized == "connected":
            result["connected"] = value
        elif normalized == "uuid":
            result["services"].append(value)
    return result


def _normalize_mac(value: str) -> str:
    clean = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(clean) != 12:
        return ""
    return ":".join(clean[index:index + 2] for index in range(0, 12, 2)).upper()


def _infer_device_type(name: str, services: list[str], device_class: str) -> str:
    text = " ".join((name, " ".join(services), device_class)).lower()
    rules = (
        (("airpods", "buds", "headset", "audio", "speaker"), "Audio"),
        (("keyboard", "clavier"), "Clavier"),
        (("mouse", "souris"), "Souris"),
        (("watch", "montre"), "Montre connectée"),
        (("phone", "iphone", "galaxy", "pixel"), "Téléphone"),
        (("tv", "television"), "Téléviseur"),
        (("car", "auto"), "Système automobile"),
    )
    for indicators, label in rules:
        if any(indicator in text for indicator in indicators):
            return label
    return "Appareil Bluetooth inconnu"

from __future__ import annotations

import platform
import shutil
import subprocess


def wifi_inventory() -> dict[str, object]:
    system = platform.system()
    if system == "Windows":
        return _run_inventory(
            ["netsh", "wlan", "show", "interfaces"],
            "netsh",
            "Informations de l'interface Wi-Fi courante.",
        )
    if shutil.which("termux-wifi-connectioninfo"):
        return _run_inventory(
            ["termux-wifi-connectioninfo"],
            "Termux:API",
            "Connexion Wi-Fi Android courante.",
        )
    if shutil.which("nmcli"):
        return _run_inventory(
            ["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY", "device", "wifi", "list"],
            "nmcli",
            "Réseaux Wi-Fi visibles selon NetworkManager.",
        )
    if shutil.which("iwgetid"):
        return _run_inventory(["iwgetid"], "iwgetid", "Connexion Wi-Fi courante.")
    return {
        "available": False,
        "engine": "-",
        "description": "Aucun outil Wi-Fi compatible détecté.",
        "output": "",
    }


def bluetooth_inventory() -> dict[str, object]:
    system = platform.system()
    if system == "Windows":
        return _run_inventory(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-PnpDevice -Class Bluetooth | Select-Object Status,FriendlyName",
            ],
            "Get-PnpDevice",
            "Périphériques Bluetooth connus de Windows.",
        )
    if shutil.which("bluetoothctl"):
        return _run_inventory(
            ["bluetoothctl", "devices"],
            "bluetoothctl",
            "Périphériques Bluetooth connus de BlueZ.",
        )
    return {
        "available": False,
        "engine": "-",
        "description": (
            "Aucun outil Bluetooth compatible détecté. Android et Termux "
            "dépendent fortement des permissions et API disponibles."
        ),
        "output": "",
    }


def _run_inventory(command: list[str], engine: str, description: str) -> dict[str, object]:
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {
            "available": False,
            "engine": engine,
            "description": f"{description} Erreur : {exc}",
            "output": "",
        }
    output = process.stdout.strip() or process.stderr.strip()
    return {
        "available": process.returncode == 0,
        "engine": engine,
        "description": description,
        "output": output,
    }

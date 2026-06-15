from __future__ import annotations

from datetime import datetime
import json
import locale
import platform
from typing import Any
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


WEATHER_CODES = {
    0: "Ciel dégagé",
    1: "Principalement dégagé",
    2: "Partiellement nuageux",
    3: "Couvert",
    45: "Brouillard",
    48: "Brouillard givrant",
    51: "Bruine faible",
    53: "Bruine modérée",
    55: "Bruine forte",
    61: "Pluie faible",
    63: "Pluie modérée",
    65: "Pluie forte",
    71: "Neige faible",
    73: "Neige modérée",
    75: "Neige forte",
    80: "Averses faibles",
    81: "Averses modérées",
    82: "Averses fortes",
    95: "Orage",
}


def local_context() -> dict[str, str]:
    now = datetime.now().astimezone()
    return {
        "date": now.strftime("%d/%m/%Y"),
        "time": now.strftime("%H:%M:%S"),
        "timezone": str(now.tzinfo or "inconnu"),
        "utc_offset": now.strftime("%z"),
        "locale": locale.getlocale()[0] or "inconnue",
        "platform": platform.system(),
    }


def weather_for_coordinates(latitude: float, longitude: float) -> dict[str, Any]:
    if not -90 <= latitude <= 90 or not -180 <= longitude <= 180:
        raise ValueError("Coordonnées invalides.")
    query = urlencode(
        {
            "latitude": latitude,
            "longitude": longitude,
            "current": "temperature_2m,apparent_temperature,weather_code,wind_speed_10m",
            "timezone": "auto",
        }
    )
    request = Request(
        f"https://api.open-meteo.com/v1/forecast?{query}",
        headers={"User-Agent": "CyberToolbox/2.10"},
    )
    try:
        with urlopen(request, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ValueError(f"Météo indisponible : {exc}") from exc
    current = payload.get("current", {})
    code = int(current.get("weather_code", -1))
    return {
        "latitude": latitude,
        "longitude": longitude,
        "timezone": payload.get("timezone", "inconnu"),
        "time": current.get("time", ""),
        "temperature": current.get("temperature_2m", ""),
        "apparent_temperature": current.get("apparent_temperature", ""),
        "wind_speed": current.get("wind_speed_10m", ""),
        "description": WEATHER_CODES.get(code, f"Code météo {code}"),
        "source": "Open-Meteo",
    }

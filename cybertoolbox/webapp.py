from __future__ import annotations

from dataclasses import asdict
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import socket
from typing import Any
from urllib.parse import parse_qs, quote, urlparse
import webbrowser

from .device_profile import build_device_profile
from .labs.http_headers import analyze_headers, fetch_headers
from .labs.local_lab import prepare_lab
from .labs.cracking import crack_wpa2_demo, derive_wpa2_pmk
from .labs.wireless import (
    bluetooth_inventory,
    local_device_identity,
    wifi_scan,
    wireless_diagnostics,
)
from .reports import list_reports, read_report, save_professional_report
from .settings import Settings, load_settings, save_settings, settings_summary


PROJECT_ROOT = Path(__file__).resolve().parent.parent

CSS = """
:root{color-scheme:dark;--bg:#050807;--panel:rgba(8,18,15,.93);
--line:rgba(77,255,168,.25);--signal:#4dffa8;--accent:#c8ff4d;
--text:#e6fff2;--muted:#83a895;--danger:#ff5c72}
*{box-sizing:border-box}html{background:var(--bg)}body{min-height:100vh;margin:0;
color:var(--text);font:15px/1.55 "Cascadia Code","JetBrains Mono",Consolas,monospace;
background:linear-gradient(rgba(77,255,168,.025) 1px,transparent 1px),
linear-gradient(90deg,rgba(77,255,168,.025) 1px,transparent 1px),
radial-gradient(circle at 85% 10%,rgba(77,255,168,.1),transparent 30%),#050807;
background-size:28px 28px,28px 28px,auto,auto}body:after{content:"";position:fixed;
inset:0;pointer-events:none;background:repeating-linear-gradient(0deg,transparent 0 3px,
rgba(255,255,255,.012) 4px)}a{color:var(--signal);text-decoration:none}
a:hover{color:var(--accent)}.shell{min-height:100vh;display:grid;
grid-template-columns:250px minmax(0,1fr)}.sidebar{position:sticky;top:0;height:100vh;
padding:24px 18px;border-right:1px solid var(--line);background:rgba(3,9,7,.95)}
.brand{margin-bottom:30px;letter-spacing:.08em}.brand strong{display:block;
color:var(--signal);font-size:18px}.brand small,.muted,.eyebrow{color:var(--muted)}
.status{display:flex;gap:8px;align-items:center;margin-top:10px;font-size:11px}
.pulse{width:8px;height:8px;border-radius:50%;background:var(--signal);
box-shadow:0 0 12px var(--signal);animation:pulse 1.8s infinite}
@keyframes pulse{50%{opacity:.35}}nav{display:grid;gap:6px}nav a{padding:10px 12px;
color:var(--muted);border-left:2px solid transparent}nav a:hover{color:var(--text);
border-color:var(--signal);background:rgba(77,255,168,.06)}main{min-width:0;
padding:30px clamp(18px,4vw,54px) 60px}.topline{display:flex;justify-content:
space-between;gap:16px;align-items:baseline;border-bottom:1px solid var(--line);
margin-bottom:28px}h1{margin:0 0 12px;font-size:clamp(24px,4vw,42px);
letter-spacing:-.04em}h1:before{content:"// ";color:var(--signal)}h2{color:
var(--signal);font-size:16px;letter-spacing:.06em;text-transform:uppercase}
.eyebrow{text-transform:uppercase;letter-spacing:.16em;font-size:11px}.grid{display:
grid;grid-template-columns:repeat(12,1fr);gap:16px}.card{grid-column:span 4;
position:relative;overflow:hidden;padding:20px;border:1px solid var(--line);
background:var(--panel);box-shadow:0 0 30px rgba(40,255,145,.08)}.card:before{
content:"";position:absolute;width:70px;height:2px;right:0;top:0;background:
var(--signal);box-shadow:0 0 12px var(--signal)}.card.wide{grid-column:span 8}
.card.full{grid-column:1/-1}.metric{color:var(--accent);font-size:30px;font-weight:700}
.button,button{display:inline-block;border:1px solid var(--signal);padding:10px 15px;
color:#03100a;background:var(--signal);font:inherit;font-weight:700;cursor:pointer;
clip-path:polygon(0 0,calc(100% - 8px) 0,100% 8px,100% 100%,0 100%)}
.button:hover,button:hover{background:var(--accent);color:#03100a}form{display:grid;
gap:14px}label{display:grid;gap:6px;color:var(--muted)}input,select,textarea{width:100%;
border:1px solid var(--line);background:#07100d;color:var(--text);padding:11px 12px;
font:inherit;outline:none}input:focus,select:focus,textarea:focus{border-color:var(--signal)}
input[type=checkbox]{width:auto;accent-color:var(--signal)}.check{display:flex;
align-items:flex-start;gap:9px}.notice{padding:13px 15px;border-left:3px solid
var(--signal);background:rgba(12,30,24,.82);margin-bottom:16px}.error{border-color:
var(--danger);color:#ffdce1}table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:10px;border-bottom:1px solid var(--line);text-align:left;
vertical-align:top}th{color:var(--signal)}pre{max-width:100%;overflow:auto;
white-space:pre-wrap;word-break:break-word;padding:16px;border:1px solid var(--line);
background:#020604;color:#c9fbe0}ul.clean{padding:0;list-style:none}ul.clean li{
padding:9px 0;border-bottom:1px dashed var(--line)}.hero{max-width:850px;margin:6vh auto}
.hero .card{padding:clamp(22px,5vw,46px)}
@media(max-width:900px){.shell{grid-template-columns:1fr}.sidebar{position:relative;
height:auto;border-right:0;border-bottom:1px solid var(--line)}.brand{margin-bottom:14px}
nav{display:flex;overflow-x:auto}nav a{white-space:nowrap;border-left:0;
border-bottom:2px solid transparent}.card,.card.wide{grid-column:span 6}}
@media(max-width:600px){main{padding:22px 14px 40px}.card,.card.wide,.card.full{
grid-column:1/-1}.topline{display:block}table{display:block;overflow-x:auto}}
"""


def _value(value: Any) -> str:
    if isinstance(value, dict):
        rows = "".join(
            f"<tr><th>{escape(str(key))}</th><td>{_value(item)}</td></tr>"
            for key, item in value.items()
        )
        return f"<table>{rows}</table>"
    if isinstance(value, list):
        return (
            "<ul class='clean'>"
            + "".join(f"<li>{_value(item)}</li>" for item in value)
            + "</ul>"
            if value
            else "<span class='muted'>Aucune donnée</span>"
        )
    return escape(str(value if value not in {"", None} else "-"))


def _field(data: dict[str, list[str]], name: str, default: str = "") -> str:
    return data.get(name, [default])[0].strip()


def _checked(data: dict[str, list[str]], name: str) -> bool:
    return _field(data, name) in {"1", "on", "true", "yes"}


class WebState:
    def __init__(self) -> None:
        self.token = secrets.token_urlsafe(32)
        self.accepted = False
        self.result: dict[str, Any] | None = None
        self.result_title = ""
        self.result_route = ""
        self.message = ""
        self.error = ""


def render_layout(title: str, body: str, accepted: bool = True) -> str:
    if not accepted:
        return (
            '<!doctype html><html lang="fr"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>{escape(title)}</title><style>{CSS}</style></head>"
            f'<body><main class="hero">{body}</main></body></html>'
        )
    nav = """<nav><a href="/">Tableau de bord</a><a href="/profile">Profil appareil</a>
<a href="/headers">Audit HTTP</a><a href="/lab">Laboratoire</a>
<a href="/wireless">Sans-fil</a><a href="/reports">Rapports</a>
<a href="/settings">Paramètres</a></nav>"""
    return f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title><style>{CSS}</style></head><body><div class="shell">
<aside class="sidebar"><div class="brand"><strong>CYBER//TOOLBOX</strong>
<small>LOCAL OPERATIONS CONSOLE</small><div class="status"><span class="pulse"></span>
SESSION LOCALE ACTIVE</div></div>{nav}</aside><main><div class="topline"><div>
<span class="eyebrow">Interface sécurisée</span><h1>{escape(title)}</h1></div>
<span class="muted">LOCAL // AUTHORIZED</span></div>{body}</main></div></body></html>"""


class ToolboxHandler(BaseHTTPRequestHandler):
    server_version = "CyberToolboxGUI/1.0"

    @property
    def state(self) -> WebState:
        return self.server.state  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        route = urlparse(self.path)
        if not self.state.accepted and route.path != "/":
            self._redirect("/")
            return
        handlers = {
            "/": self._home,
            "/profile": self._profile,
            "/headers": self._headers,
            "/lab": self._lab,
            "/wireless": self._wireless,
            "/reports": self._reports,
            "/report": lambda: self._report(route.query),
            "/settings": self._settings,
        }
        handler = handlers.get(route.path)
        if not handler:
            self._send(render_layout("Introuvable", "<div class='notice error'>Page introuvable.</div>"), 404)
            return
        handler()

    def do_POST(self) -> None:
        size = int(self.headers.get("Content-Length", "0"))
        data = parse_qs(self.rfile.read(size).decode("utf-8", errors="replace"))
        if _field(data, "token") != self.state.token:
            self._send(render_layout("Requête refusée", "<div class='notice error'>Jeton invalide.</div>"), 403)
            return
        handlers = {
            "/accept": lambda: self._accept(data),
            "/profile": lambda: self._run_profile(data),
            "/headers": lambda: self._run_headers(data),
            "/lab": self._prepare_lab,
            "/wireless": lambda: self._run_wireless(data),
            "/settings": lambda: self._save_settings(data),
        }
        handler = handlers.get(urlparse(self.path).path)
        if not handler:
            self._send(render_layout("Introuvable", "<div class='notice error'>Action introuvable.</div>"), 404)
            return
        handler()

    def _token(self) -> str:
        return f'<input type="hidden" name="token" value="{escape(self.state.token)}">'

    def _result(self, route: str) -> str:
        if self.state.error:
            return f"<div class='card full notice error'><strong>ERREUR</strong><br>{escape(self.state.error)}</div>"
        if not self.state.result or self.state.result_route != route:
            return ""
        return f"<section class='card full'><h2>{escape(self.state.result_title)}</h2>{_value(self.state.result)}</section>"

    def _home(self) -> None:
        if not self.state.accepted:
            body = f"""<section class="card full"><span class="eyebrow">Accès contrôlé</span>
<h1>Cyber Learning Toolbox</h1><p>Cette console est réservée à l'apprentissage,
aux laboratoires locaux et aux appareils explicitement autorisés.</p>
<div class="notice">Les profils restent techniques. Ils ne servent pas à
identifier, suivre ou surveiller une personne.</div><form method="post" action="/accept">
{self._token()}<label class="check"><input type="checkbox" name="accepted" required>
Je confirme respecter le périmètre autorisé et la législation applicable.</label>
<button type="submit">INITIALISER LA SESSION</button></form></section>"""
            self._send(render_layout("Autorisation", body, accepted=False))
            return
        settings = load_settings()
        body = f"""<div class="grid"><section class="card wide">
<span class="eyebrow">Système opérationnel</span><h2>Console d'apprentissage</h2>
<p>Explorez une chaîne d'audit depuis un navigateur. Les commandes terminal
restent disponibles et les mêmes limites de sécurité sont appliquées.</p>
<a class="button" href="/profile">NOUVEAU PROFIL</a></section>
<section class="card"><span class="eyebrow">Archives</span>
<div class="metric">{len(list_reports()):02d}</div><p>rapports disponibles</p></section>
<section class="card"><h2>Profil appareil</h2><p>IP, MAC visible, services,
type probable et confiance.</p><a href="/profile">OUVRIR &gt;</a></section>
<section class="card"><h2>Audit HTTP</h2><p>Contrôle passif des en-têtes de
sécurité.</p><a href="/headers">OUVRIR &gt;</a></section>
<section class="card"><h2>Lab local</h2><p>Journaux suspects, payload factice
et script risqué.</p><a href="/lab">OUVRIR &gt;</a></section>
<section class="card"><h2>Wi-Fi et Bluetooth</h2><p>Scan visible, diagnostic,
profil local et lab WPA2 hors ligne.</p><a href="/wireless">OUVRIR &gt;</a></section>
<section class="card full"><h2>Configuration active</h2>
{_value(dict(settings_summary(settings)))}</section></div>"""
        self._send(render_layout("Tableau de bord", body))

    def _accept(self, data: dict[str, list[str]]) -> None:
        if _checked(data, "accepted"):
            self.state.accepted = True
        self._redirect("/")

    def _profile(self) -> None:
        settings = load_settings()
        body = f"""<div class="grid"><section class="card wide">
<h2>Acquisition autorisée</h2><p class="muted">Le scan est limité aux adresses
privées et locales. Nmap est utilisé s'il est disponible.</p>
<form method="post" action="/profile">{self._token()}
<label>Cible<input name="target" placeholder="192.168.1.25 ou localhost" required></label>
<label>Ports<input name="ports" value="{escape(settings.default_ports)}" required></label>
<label class="check"><input type="checkbox" name="authorized" required>
Je dispose de l'autorisation du propriétaire ou responsable.</label>
<label class="check"><input type="checkbox" name="report">Générer un rapport.</label>
<button type="submit">LANCER LE PROFIL</button></form></section>
<section class="card"><h2>Observations</h2><ul class="clean"><li>Adresse et nom</li>
<li>MAC locale</li><li>Services exposés</li><li>Type probable</li></ul></section>
{self._result("/profile")}</div>"""
        self._send(render_layout("Profil d'appareil", body))

    def _run_profile(self, data: dict[str, list[str]]) -> None:
        self._clear()
        try:
            if not _checked(data, "authorized"):
                raise ValueError("L'autorisation explicite est obligatoire.")
            settings = load_settings()
            profile = build_device_profile(
                _field(data, "target"),
                _field(data, "ports", settings.default_ports),
                settings.scan_timeout,
                settings.prefer_nmap,
                settings.internet_correlation,
            )
            result = asdict(profile)
            create_report = settings.report_mode == "auto" or (
                settings.report_mode != "off" and _checked(data, "report")
            )
            if create_report:
                services = ", ".join(
                    f"{item.get('port')}/{item.get('service', 'inconnu')}"
                    for item in profile.services
                ) or "Aucun service détecté"
                path = save_professional_report(
                    f"Profil technique {profile.address}",
                    f"Appareil {profile.address}, autorisation confirmée.",
                    f"Type probable : {profile.device_type} ({profile.confidence}).",
                    [{"severity": "information", "title": "Services observés",
                      "evidence": services, "impact": "Surface réseau à valider."}],
                    ["Désactiver les services inutiles.", "Maintenir les logiciels à jour."],
                    "Estimation technique, sans identification personnelle.",
                )
                result["rapport"] = str(path)
            self.state.result_title = "Résultat du profil"
            self.state.result_route = "/profile"
            self.state.result = result
        except (ValueError, OSError) as exc:
            self.state.error = str(exc)
        self._redirect("/profile")

    def _headers(self) -> None:
        body = f"""<div class="grid"><section class="card wide"><h2>Analyse passive</h2>
<p class="muted">Une requête HEAD examine la configuration exposée. Aucune
injection n'est tentée.</p><form method="post" action="/headers">{self._token()}
<label>URL<input type="url" name="url" placeholder="https://example.org" required></label>
<button type="submit">ANALYSER</button></form></section>
<section class="card"><h2>Contrôles</h2><ul class="clean"><li>CSP</li><li>HSTS</li>
<li>Referrer-Policy</li><li>Permissions-Policy</li></ul></section>
{self._result("/headers")}</div>"""
        self._send(render_layout("Audit HTTP", body))

    def _run_headers(self, data: dict[str, list[str]]) -> None:
        self._clear()
        try:
            url = _field(data, "url")
            status, headers = fetch_headers(url)
            self.state.result_title = "Configuration HTTP"
            self.state.result_route = "/headers"
            self.state.result = {
                "URL": url,
                "Statut": status,
                "Constats": analyze_headers(headers, url.startswith("https://")),
                "En-têtes": headers,
            }
        except (ValueError, OSError) as exc:
            self.state.error = str(exc)
        self._redirect("/headers")

    def _lab(self) -> None:
        body = f"""<div class="grid"><section class="card wide">
<h2>Zone d'entraînement locale</h2><p>Générez un journal suspect, un payload
texte et un script volontairement risqué.</p><form method="post" action="/lab">
{self._token()}<button type="submit">PRÉPARER LES ARTEFACTS</button></form></section>
<section class="card"><h2>Garantie</h2><p class="muted">Aucun payload n'est
exécuté. Tout reste dans <code>lab_workspace</code>.</p></section>
{self._result("/lab")}</div>"""
        self._send(render_layout("Laboratoire local", body))

    def _prepare_lab(self) -> None:
        self._clear()
        try:
            artifacts = prepare_lab(PROJECT_ROOT / "lab_workspace")
            self.state.result_title = "Artefacts prêts"
            self.state.result_route = "/lab"
            self.state.result = {
                name: str(path.relative_to(PROJECT_ROOT)) for name, path in artifacts.items()
            }
        except OSError as exc:
            self.state.error = str(exc)
        self._redirect("/lab")

    def _reports(self) -> None:
        items = "".join(
            f'<li><a href="/report?name={quote(path.name)}">{escape(path.name)}</a></li>'
            for path in list_reports()
        ) or "<li class='muted'>Aucun rapport disponible.</li>"
        self._send(render_layout(
            "Rapports",
            f"<section class='card full'><h2>Archives Markdown</h2><ul class='clean'>{items}</ul></section>",
        ))

    def _wireless(self) -> None:
        body = f"""<div class="grid"><section class="card wide">
<h2>Environnement sans-fil</h2><p class="muted">Toutes les collectes utilisent
les API autorisées du système. Aucun appairage, connexion, capture ou paquet de
désauthentification n'est émis.</p><form method="post" action="/wireless">
{self._token()}<label>Action<select name="action">
<option value="wifi">Réseaux Wi-Fi visibles</option>
<option value="bluetooth">Bluetooth connu ou visible</option>
<option value="environment">Profil de l'appareil courant</option>
<option value="diagnostic">Diagnostic des capacités</option>
</select></label><button type="submit">EXÉCUTER</button></form></section>
<section class="card"><h2>Lab WPA2 hors ligne</h2>
<form method="post" action="/wireless">{self._token()}
<input type="hidden" name="action" value="wifi_lab">
<label>SSID fictif<input name="ssid" value="CTOS-LAB" required></label>
<label>Mot de passe temporaire<input type="password" name="secret" required></label>
<label>Candidats, un par ligne<textarea name="candidates" rows="6"
required>motdepasse
classe-2026
password</textarea></label>
<button type="submit">TESTER HORS LIGNE</button></form></section>
{self._result("/wireless")}</div>"""
        self._send(render_layout("Wi-Fi et Bluetooth", body))

    def _run_wireless(self, data: dict[str, list[str]]) -> None:
        self._clear()
        try:
            action = _field(data, "action")
            if action == "wifi":
                result = wifi_scan()
            elif action == "bluetooth":
                result = bluetooth_inventory()
            elif action == "environment":
                result = {
                    "identity": local_device_identity(),
                    "wifi": wifi_scan(),
                    "bluetooth": bluetooth_inventory(),
                }
            elif action == "diagnostic":
                result = wireless_diagnostics()
            elif action == "wifi_lab":
                ssid = _field(data, "ssid", "CTOS-LAB")
                secret = _field(data, "secret")
                candidates = _field(data, "candidates").splitlines()
                result = crack_wpa2_demo(
                    ssid,
                    derive_wpa2_pmk(ssid, secret),
                    candidates,
                )
                result["notice"] = (
                    "Le secret est affiché uniquement dans cette page et n'est pas enregistré."
                )
            else:
                raise ValueError("Action sans-fil inconnue.")
            self.state.result_title = "Résultat sans-fil"
            self.state.result_route = "/wireless"
            self.state.result = result
        except (ValueError, OSError) as exc:
            self.state.error = str(exc)
        self._redirect("/wireless")

    def _report(self, query: str) -> None:
        name = parse_qs(query).get("name", [""])[0]
        report = next((path for path in list_reports() if path.name == name), None)
        if not report:
            self._send(render_layout("Rapport introuvable", "<div class='notice error'>Rapport invalide.</div>"), 404)
            return
        self._send(render_layout(
            report.name,
            f"<section class='card full'><pre>{escape(read_report(report))}</pre></section>",
        ))

    def _settings(self) -> None:
        settings = load_settings()
        feedback = ""
        if self.state.message:
            feedback = f"<div class='notice'>{escape(self.state.message)}</div>"
            self.state.message = ""
        if self.state.error:
            feedback = f"<div class='notice error'>{escape(self.state.error)}</div>"
            self.state.error = ""
        body = f"""{feedback}<section class="card full"><h2>Préférences locales</h2>
<form method="post" action="/settings">{self._token()}
<label>Langue<select name="language">
<option value="fr"{" selected" if settings.language == "fr" else ""}>Français</option>
<option value="en"{" selected" if settings.language == "en" else ""}>English</option>
</select></label><label>Rapports<select name="report_mode">
<option value="ask"{" selected" if settings.report_mode == "ask" else ""}>Demander</option>
<option value="auto"{" selected" if settings.report_mode == "auto" else ""}>Automatique</option>
<option value="off"{" selected" if settings.report_mode == "off" else ""}>Désactivé</option>
</select></label><label>Ports par défaut
<input name="default_ports" value="{escape(settings.default_ports)}"></label>
<label>Délai TCP<input type="number" step="0.1" min="0.1" max="5"
name="scan_timeout" value="{settings.scan_timeout}"></label>
<label class="check"><input type="checkbox" name="prefer_nmap"{" checked" if settings.prefer_nmap else ""}>Préférer Nmap.</label>
<label class="check"><input type="checkbox" name="show_lessons"{" checked" if settings.show_lessons else ""}>Afficher les explications.</label>
<label class="check"><input type="checkbox" name="internet_correlation"{" checked" if settings.internet_correlation else ""}>Autoriser la corrélation DNS.</label>
<button type="submit">ENREGISTRER</button></form></section>"""
        self._send(render_layout("Paramètres", body))

    def _save_settings(self, data: dict[str, list[str]]) -> None:
        try:
            settings = Settings(
                language=_field(data, "language", "fr"),
                report_mode=_field(data, "report_mode", "ask"),
                default_ports=_field(data, "default_ports", "1-1024"),
                prefer_nmap=_checked(data, "prefer_nmap"),
                show_lessons=_checked(data, "show_lessons"),
                internet_correlation=_checked(data, "internet_correlation"),
                scan_timeout=float(_field(data, "scan_timeout", "0.4")),
            )
            save_settings(settings)
            self.state.message = "Paramètres enregistrés."
        except (ValueError, OSError) as exc:
            self.state.error = str(exc)
        self._redirect("/settings")

    def _clear(self) -> None:
        self.state.result = None
        self.state.result_title = ""
        self.state.result_route = ""
        self.state.error = ""

    def _redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.end_headers()

    def _send(self, content: str, status: int = 200) -> None:
        payload = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        print(f"[GUI] {self.address_string()} - {format % args}")


class ToolboxServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int]) -> None:
        super().__init__(address, ToolboxHandler)
        self.state = WebState()


def serve_gui(port: int = 8765, lan: bool = False, open_browser: bool = True) -> None:
    if port < 1024 or port > 65535:
        raise ValueError("Choisissez un port entre 1024 et 65535.")
    host = "0.0.0.0" if lan else "127.0.0.1"
    server = ToolboxServer((host, port))
    local_url = f"http://127.0.0.1:{port}"
    print("\nCYBER TOOLBOX // INTERFACE GRAPHIQUE")
    print(f"Adresse locale : {local_url}")
    if lan:
        try:
            address = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            address = "<adresse-ip-du-pc>"
        print(f"Accès réseau privé : http://{address}:{port}")
        print("Utilisez --lan uniquement sur un réseau de confiance.")
    print("Arrêt : Ctrl+C")
    if open_browser:
        try:
            webbrowser.open(local_url)
        except webbrowser.Error:
            pass
    try:
        server.serve_forever()
    finally:
        server.server_close()

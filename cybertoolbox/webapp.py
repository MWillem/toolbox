from __future__ import annotations

from dataclasses import asdict
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import socket
import time
from typing import Any
from urllib.parse import parse_qs, quote, urlparse
import webbrowser

from .context_info import local_context, weather_for_coordinates
from .device_profile import build_device_profile
from .exposure import exposure_inventory
from .history import (
    delete_all_history,
    delete_history,
    history_display_name,
    list_history,
    load_history,
    rename_history,
    save_history,
)
from .labs.crypto_basics import base64_decode, base64_encode
from .labs.file_audit import audit_local_configuration, audit_path
from .labs.http_headers import analyze_headers, fetch_headers
from .labs.local_lab import prepare_lab
from .labs.log_analysis import analyze_log
from .labs.network import discover_hosts, scan_ports
from .labs.hashing import hash_text
from .labs.network_info import dns_lookup, inspect_tls
from .labs.passwords import analyze_password
from .labs.payloads import analyze_payload_file
from .labs.script_analysis import analyze_script
from .labs.system_audit import audit_system
from .labs.cracking import crack_wpa2_demo, derive_wpa2_pmk
from .labs.wireless import (
    bluetooth_inventory,
    local_device_identity,
    mobile_operator_info,
    wifi_scan,
    wireless_diagnostics,
)
from .mission import (
    delete_all_missions,
    delete_mission,
    list_missions,
    rename_mission,
)
from .reports import (
    delete_all_reports,
    delete_report,
    list_reports,
    read_report,
    rename_report,
    save_professional_report,
)
from .settings import Settings, load_settings, save_settings, settings_summary


PROJECT_ROOT = Path(__file__).resolve().parent.parent

CSS = """
:root{color-scheme:dark;--bg:#050506;--panel:rgba(13,13,15,.94);
--line:rgba(255,255,255,.18);--signal:#d600a9;--accent:#51d414;
--text:#f2f2f2;--muted:#9b9b9f;--danger:#ff4d59;--orange:#ff9d00;
--glow:rgba(214,0,169,.18);--field:rgba(7,16,13,.72);--radius:16px}
body[data-theme="github"]{--bg:#0d1117;--panel:rgba(22,27,34,.76);
--signal:#58a6ff;--accent:#79c0ff;--glow:rgba(88,166,255,.2);--field:rgba(13,17,23,.78)}
body[data-theme="terminal"]{--bg:#020805;--panel:rgba(4,20,12,.76);
--signal:#39ff88;--accent:#b6ff3b;--glow:rgba(57,255,136,.18);--field:rgba(2,14,8,.8)}
body[data-theme="ocean"]{--bg:#06121b;--panel:rgba(8,31,45,.76);
--signal:#00c8ff;--accent:#00ffd0;--glow:rgba(0,200,255,.2);--field:rgba(4,24,35,.8)}
body[data-theme="amber"]{--bg:#110b03;--panel:rgba(32,21,7,.78);
--signal:#ffad22;--accent:#ffe066;--glow:rgba(255,173,34,.2);--field:rgba(25,15,4,.8)}
*{box-sizing:border-box}html{background:var(--bg)}body{min-height:100vh;margin:0;
color:var(--text);font:15px/1.55 "Cascadia Code","JetBrains Mono",Consolas,monospace;
background:linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px),
linear-gradient(90deg,rgba(255,255,255,.018) 1px,transparent 1px),
radial-gradient(circle at 85% 10%,var(--glow),transparent 30%),var(--bg);
background-size:28px 28px,28px 28px,auto,auto}body:after{content:"";position:fixed;
inset:0;pointer-events:none;background:repeating-linear-gradient(0deg,transparent 0 3px,
rgba(255,255,255,.012) 4px)}a{color:var(--signal);text-decoration:none}
a:hover{color:var(--accent)}.shell{min-height:100vh;display:grid;
grid-template-columns:250px minmax(0,1fr);transition:grid-template-columns .25s ease}
.sidebar{position:sticky;top:0;height:100vh;padding:24px 18px;border-right:1px solid var(--line);
background:var(--panel);backdrop-filter:blur(24px) saturate(130%);
transition:transform .25s ease,opacity .2s ease;z-index:20}.shell.nav-collapsed{
grid-template-columns:0 minmax(0,1fr)}.shell.nav-collapsed .sidebar{
transform:translateX(-102%);opacity:0;pointer-events:none}
.brand{margin-bottom:30px;letter-spacing:.08em}.brand strong{display:block;
color:var(--signal);font-size:18px}.brand small,.muted,.eyebrow{color:var(--muted)}
.status{display:flex;gap:8px;align-items:center;margin-top:10px;font-size:11px}
.pulse{width:8px;height:8px;border-radius:50%;background:var(--signal);
box-shadow:0 0 12px var(--signal);animation:pulse 1.8s infinite}
@keyframes pulse{50%{opacity:.35}}nav{display:grid;gap:6px}nav a{padding:10px 12px;
color:var(--muted);border-left:2px solid transparent}nav a:hover{color:var(--text);
border-color:var(--signal);background:rgba(214,0,169,.1)}main{min-width:0;
padding:30px clamp(18px,4vw,54px) 60px}.topline{display:flex;justify-content:
space-between;gap:16px;align-items:baseline;border-bottom:1px solid var(--line);
margin-bottom:28px}h1{margin:0 0 12px;font-size:clamp(24px,4vw,42px);
letter-spacing:-.04em}h1:before{content:"// ";color:var(--signal)}h2{color:
var(--signal);font-size:16px;letter-spacing:.06em;text-transform:uppercase}
.eyebrow{text-transform:uppercase;letter-spacing:.16em;font-size:11px}.grid{display:
grid;grid-template-columns:repeat(12,1fr);gap:16px}.card{grid-column:span 4;
position:relative;overflow:hidden;padding:20px;border:1px solid var(--line);
background:var(--panel);backdrop-filter:blur(22px) saturate(125%);
box-shadow:0 14px 45px var(--glow)}.no-glass .card,.no-glass .sidebar,
.no-glass .loading-panel{backdrop-filter:none}.no-glass{--panel:#101014;
--field:#07100d}.card:before{
content:"";position:absolute;width:70px;height:2px;right:0;top:0;background:
var(--signal);box-shadow:0 0 12px var(--signal)}.card.wide{grid-column:span 8}
.card.full{grid-column:1/-1}.metric{color:var(--accent);font-size:30px;font-weight:700}
.app-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.app{min-height:120px;padding:16px;border:1px solid var(--line);background:var(--panel);
backdrop-filter:blur(16px);
display:flex;flex-direction:column;justify-content:space-between}.app strong{color:var(--text)}
.app span{color:var(--muted);font-size:12px}.app:hover{border-color:var(--signal);
box-shadow:0 0 22px rgba(214,0,169,.16)}.group-label{margin:22px 0 8px;color:var(--signal);
letter-spacing:.12em;font-size:11px;text-transform:uppercase}.context-bar{display:flex;
gap:18px;flex-wrap:wrap;padding:10px 14px;background:#d0d0d0;color:#111;font-weight:700}
.map{width:100%;min-height:430px;border:1px solid var(--line);background:#09090b}
.node{fill:#18181c;stroke:var(--accent);stroke-width:2}.node-risk{stroke:var(--orange)}
.edge{stroke:#5c5c62;stroke-width:1}.map-label{fill:#eee;font-size:12px}
.badge{display:inline-block;padding:3px 7px;border:1px solid var(--line);font-size:11px}
.menu-toggle{width:44px;height:40px;padding:0;display:grid;place-items:center;font-size:22px;
clip-path:none;background:transparent;color:var(--text)}.button,button{display:inline-block;border:1px solid var(--signal);padding:10px 15px;
color:#03100a;background:var(--signal);font:inherit;font-weight:700;cursor:pointer;
clip-path:polygon(0 0,calc(100% - 8px) 0,100% 8px,100% 100%,0 100%)}
.button:hover,button:hover{background:var(--accent);color:#03100a}form{display:grid;
gap:14px}label{display:grid;gap:6px;color:var(--muted)}input,select,textarea{width:100%;
border:1px solid var(--line);background:var(--field);color:var(--text);padding:11px 12px;
font:inherit;outline:none}input:focus,select:focus,textarea:focus{border-color:var(--signal)}
input[type=checkbox]{width:auto;accent-color:var(--signal)}.check{display:flex;
align-items:flex-start;gap:9px}.notice{padding:13px 15px;border-left:3px solid
var(--signal);background:rgba(12,30,24,.82);margin-bottom:16px}.error{border-color:
var(--danger);color:#ffdce1}.table-wrap{width:100%;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:10px;border-bottom:1px solid var(--line);text-align:left;
vertical-align:top}th{color:var(--signal)}.key-table>tbody>tr>th{width:28%;
min-width:150px}.data-table{min-width:520px}.data-table>thead>tr>th{white-space:nowrap;
background:#111114}.data-table>tbody>tr:nth-child(even){background:rgba(255,255,255,.025)}
.data-table td,.data-table th{overflow-wrap:anywhere}.loading-overlay{position:fixed;
inset:0;z-index:100;display:none;place-items:center;padding:20px;background:rgba(2,2,3,.88);
backdrop-filter:blur(5px)}.loading-overlay.active{display:grid}.loading-panel{
width:min(680px,100%);padding:24px;border:1px solid var(--signal);background:#08080a;
box-shadow:0 0 48px rgba(214,0,169,.28)}.loading-head{display:flex;
justify-content:space-between;gap:20px;color:var(--signal);font-weight:700}
.loading-track{height:5px;margin:18px 0;background:#26262a;overflow:hidden}
.loading-track:after{content:"";display:block;width:38%;height:100%;background:var(--accent);
box-shadow:0 0 12px var(--accent);animation:scan 1.15s ease-in-out infinite}
@keyframes scan{from{transform:translateX(-110%)}to{transform:translateX(285%)}}
.loading-log{height:150px;margin:0;overflow:auto;border:1px solid var(--line);
background:#020203;color:#d8d8dc;font-size:12px}.loading-log span{display:block;
padding:3px 0}.loading-log span:before{content:"> ";color:var(--accent)}
.tabs{display:flex;gap:8px;overflow-x:auto;margin-bottom:16px}.tab-button{
background:transparent;color:var(--muted);clip-path:none;border-color:var(--line)}
.tab-button.active{color:#050506;background:var(--signal);border-color:var(--signal)}
.tab-panel{display:none}.tab-panel.active{display:block}.switch{display:flex;
align-items:center;justify-content:space-between;gap:16px;padding:12px 0;
border-bottom:1px solid var(--line)}.switch input{position:absolute;opacity:0}
.switch-track{width:50px;height:28px;padding:3px;border-radius:999px;background:#3a3a40;
transition:.2s}.switch-track:after{content:"";display:block;width:22px;height:22px;
border-radius:50%;background:#fff;transition:.2s}.switch input:checked+.switch-track{
background:var(--signal)}.switch input:checked+.switch-track:after{transform:translateX(22px)}
.theme-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}
.theme-choice{position:relative}.theme-choice input{position:absolute;opacity:0}
.theme-swatch{display:block;padding:14px;border:1px solid var(--line);background:var(--panel);
cursor:pointer}.theme-choice input:checked+.theme-swatch{border-color:var(--signal);
box-shadow:0 0 20px var(--glow)}.geo-map{width:100%;height:min(62vh,620px);
border:1px solid var(--line);background:#0a0a0d}.map-controls{display:grid;
grid-template-columns:1fr 1fr auto;gap:10px;margin-bottom:12px}
pre{max-width:100%;overflow:auto;
white-space:pre-wrap;word-break:break-word;padding:16px;border:1px solid var(--line);
background:#020604;color:#c9fbe0}ul.clean{padding:0;list-style:none}ul.clean li{
padding:9px 0;border-bottom:1px dashed var(--line)}.hero{max-width:850px;margin:6vh auto}
.hero .card{padding:clamp(22px,5vw,46px)}
.sidebar{border-radius:0 var(--radius) var(--radius) 0}
nav a,.context-bar,.notice,.theme-swatch,pre,.table-wrap{border-radius:12px}
.card,.loading-panel,.map,.geo-map{border-radius:var(--radius)}
.app{border-radius:14px}.badge{border-radius:999px}
.button,button,input,select,textarea{border-radius:10px;clip-path:none}
button.danger{border-color:var(--danger);background:transparent;color:var(--danger)}
button.danger:hover{background:var(--danger);color:#fff}
.geo-map{position:relative;overflow:hidden}
.map-tile{position:absolute;width:256px;height:256px;max-width:none}
.map-marker{position:absolute;left:50%;top:50%;z-index:5;width:22px;height:22px;
transform:translate(-50%,-50%);border:4px solid #fff;border-radius:50%;
background:var(--signal);box-shadow:0 0 0 8px var(--glow),0 0 22px #000}
.map-controls{grid-template-columns:1fr 1fr 1fr 1fr auto}
.data-actions{display:flex;gap:8px;align-items:end;flex-wrap:wrap}
.data-actions form{display:flex;gap:8px;align-items:end;flex:1;min-width:220px}
.data-actions form.compact{flex:0 0 auto;min-width:0}
.ownership{margin-top:34px;padding-top:16px;border-top:1px solid var(--line);
color:var(--muted);font-size:11px}
@media(max-width:900px){.shell{grid-template-columns:1fr}.sidebar{position:fixed;
left:0;top:0;width:min(82vw,300px);height:100vh;box-shadow:20px 0 60px #000}
.shell.nav-collapsed{grid-template-columns:1fr}.brand{margin-bottom:14px}
nav{display:grid}.card,.card.wide{grid-column:span 6}}
@media(max-width:600px){main{padding:22px 14px 40px}.card,.card.wide,.card.full{
grid-column:1/-1}.topline{display:block}.table-wrap{overflow-x:auto}
.sidebar{padding:10px}.brand{display:none}.app-grid{grid-template-columns:repeat(2,1fr)}
.app{min-height:105px}.context-bar{position:sticky;top:0;z-index:4;font-size:12px}
.map-controls{grid-template-columns:1fr}.geo-map{height:56vh}}
"""


def _value(value: Any) -> str:
    if isinstance(value, dict):
        rows = "".join(
            f"<tr><th>{escape(str(key))}</th><td>{_value(item)}</td></tr>"
            for key, item in value.items()
        )
        return (
            "<div class='table-wrap'><table class='key-table'>"
            f"<tbody>{rows}</tbody></table></div>"
        )
    if isinstance(value, list):
        if value and all(isinstance(item, dict) for item in value):
            headers: list[str] = []
            for item in value:
                for key in item:
                    name = str(key)
                    if name not in headers:
                        headers.append(name)
            heading = "".join(f"<th>{escape(key)}</th>" for key in headers)
            rows = "".join(
                "<tr>"
                + "".join(f"<td>{_value(item.get(key))}</td>" for key in headers)
                + "</tr>"
                for item in value
            )
            return (
                "<div class='table-wrap'><table class='data-table'>"
                f"<thead><tr>{heading}</tr></thead><tbody>{rows}</tbody></table></div>"
            )
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


def _workspace_path(value: str) -> Path:
    if not value:
        raise ValueError("Indiquez un chemin relatif au dossier du projet.")
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    candidate = candidate.resolve()
    if not candidate.is_relative_to(PROJECT_ROOT.resolve()):
        raise ValueError("Le GUI limite l'analyse aux fichiers du dossier du projet.")
    if not candidate.exists():
        raise ValueError("Ce fichier ou dossier n'existe pas.")
    return candidate


def render_topology() -> str:
    inventory = exposure_inventory()
    assets = list(inventory["assets"].items())
    width, height = 900, 460
    center_x, center_y = width // 2, height // 2
    elements = [
        f'<svg class="map" viewBox="0 0 {width} {height}" role="img" '
        'aria-label="Carte tactique des actifs autorisés">',
        f'<circle class="node" cx="{center_x}" cy="{center_y}" r="48"/>',
        f'<text class="map-label" x="{center_x}" y="{center_y}" text-anchor="middle">TOOLBOX</text>',
    ]
    count = max(1, len(assets))
    import math

    for index, (address, asset) in enumerate(assets):
        angle = (2 * math.pi * index / count) - math.pi / 2
        x = center_x + math.cos(angle) * 300
        y = center_y + math.sin(angle) * 170
        risk = bool(asset["findings"])
        elements.append(
            f'<line class="edge" x1="{center_x}" y1="{center_y}" x2="{x:.0f}" y2="{y:.0f}"/>'
        )
        elements.append(
            f'<circle class="node{" node-risk" if risk else ""}" cx="{x:.0f}" cy="{y:.0f}" r="38"/>'
        )
        elements.append(
            f'<text class="map-label" x="{x:.0f}" y="{y - 48:.0f}" text-anchor="middle">'
            f'{escape(address)}</text>'
        )
        elements.append(
            f'<text class="map-label" x="{x:.0f}" y="{y + 4:.0f}" text-anchor="middle">'
            f'{len(asset["services"])} svc</text>'
        )
    if not assets:
        elements.append(
            '<text class="map-label" x="450" y="315" text-anchor="middle">'
            "Aucun scan enregistré</text>"
        )
    elements.append("</svg>")
    return "".join(elements)


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
    settings = load_settings()
    nav = """<nav><a href="/">Dashboard</a><a href="/operations">Opérations</a>
<a href="/recon">Recon</a>
<a href="/profile">Profiler</a><a href="/lab">Labs</a><a href="/wireless">Sans-fil</a>
<a href="/exposure">Exposition</a><a href="/map">Carte</a><a href="/reports">Données</a>
<a href="/tools">Outils</a><a href="/context">Contexte</a><a href="/settings">Réglages</a></nav>"""
    context = local_context()
    body_class = "" if settings.glass_effect else "no-glass"
    return f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title><style>{CSS}</style></head>
<body class="{body_class}" data-theme="{escape(settings.theme)}"><div class="shell" id="app-shell">
<aside class="sidebar"><div class="brand"><strong>CYBER//TOOLBOX</strong>
<small>LOCAL OPERATIONS CONSOLE</small><div class="status"><span class="pulse"></span>
SESSION LOCALE ACTIVE</div></div>{nav}</aside><main><div class="topline"><div>
<button class="menu-toggle" id="menu-toggle" type="button" aria-label="Afficher ou masquer le menu">☰</button>
<span class="eyebrow">Interface sécurisée</span><h1>{escape(title)}</h1></div>
<span class="muted">LOCAL // AUTHORIZED</span></div>
<div class="context-bar"><span id="live-clock">{escape(context['time'])}</span>
<span>{escape(context['timezone'])}</span><span>{escape(context['platform'])}</span></div>
{body}<footer class="ownership">Cyber Learning Toolbox © 2026 Maréchaux Willem ·
Projet original distribué sous licence MIT · La notice de copyright doit être conservée.</footer>
</main></div>
<div class="loading-overlay" id="loading-overlay" role="status" aria-live="polite">
<section class="loading-panel"><div class="loading-head">
<span id="loading-title">OPÉRATION EN COURS</span><span id="loading-time">00:00</span>
</div><div class="loading-track"></div><pre class="loading-log" id="loading-log"></pre>
<p class="muted">Gardez cette page ouverte. Le résultat s'affichera automatiquement.</p>
</section></div><script>
setInterval(()=>{{const e=document.getElementById('live-clock');if(e)e.textContent=new Date().toLocaleTimeString();}},1000);
function locate(){{if(!navigator.geolocation)return;navigator.geolocation.getCurrentPosition(p=>{{
document.querySelector('[name=latitude]').value=p.coords.latitude.toFixed(5);
document.querySelector('[name=longitude]').value=p.coords.longitude.toFixed(5);}});}}
const shell=document.getElementById("app-shell");
const menuToggle=document.getElementById("menu-toggle");
const savedMenu=localStorage.getItem("cybertoolbox-menu");
if(savedMenu==="closed"||(savedMenu===null&&window.innerWidth<900))shell.classList.add("nav-collapsed");
menuToggle.addEventListener("click",()=>{{
shell.classList.toggle("nav-collapsed");
localStorage.setItem("cybertoolbox-menu",shell.classList.contains("nav-collapsed")?"closed":"open");
}});
document.querySelectorAll(".sidebar a").forEach(link=>link.addEventListener("click",()=>{{
if(window.innerWidth<900)localStorage.setItem("cybertoolbox-menu","closed");
}}));
document.querySelectorAll("[data-tabs]").forEach(group=>{{
const buttons=group.querySelectorAll("[data-tab]");
const panels=group.querySelectorAll("[data-panel]");
buttons.forEach(button=>button.addEventListener("click",()=>{{
buttons.forEach(item=>item.classList.remove("active"));
panels.forEach(item=>item.classList.remove("active"));
button.classList.add("active");
group.querySelector(`[data-panel="${{button.dataset.tab}}"]`)?.classList.add("active");
}}));
}});
document.querySelectorAll("[name=theme]").forEach(choice=>choice.addEventListener("change",()=>{{
document.body.dataset.theme=choice.value;
}}));
document.querySelector("[name=glass_effect]")?.addEventListener("change",event=>{{
document.body.classList.toggle("no-glass",!event.target.checked);
}});
const mapProviders={{
standard:{{url:"https://tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png",
label:"OpenStreetMap Standard",maxZoom:19}},
humanitarian:{{url:"https://a.tile.openstreetmap.fr/hot/{{z}}/{{x}}/{{y}}.png",
label:"Humanitarian OpenStreetMap",maxZoom:19}},
cycle:{{url:"https://a.tile.openstreetmap.fr/cyclosm/{{z}}/{{x}}/{{y}}.png",
label:"CyclOSM",maxZoom:20}},
topographic:{{url:"https://a.tile.opentopomap.org/{{z}}/{{x}}/{{y}}.png",
label:"OpenTopoMap",maxZoom:17}}
}};
function showGeoMap(latitude,longitude){{
let lat=Number(latitude);const lon=Number(longitude);
if(!Number.isFinite(lat)||!Number.isFinite(lon)||lat<-90||lat>90||lon<-180||lon>180)return;
lat=Math.max(-85.05112878,Math.min(85.05112878,lat));
const map=document.getElementById("geo-map-frame");
const provider=mapProviders[document.getElementById("map-layer").value]||mapProviders.standard;
const requestedZoom=Number(document.getElementById("map-zoom").value)||15;
const zoom=Math.min(requestedZoom,provider.maxZoom);
const n=2**zoom;
const x=(lon+180)/360*n;
const latRad=lat*Math.PI/180;
const y=(1-Math.asinh(Math.tan(latRad))/Math.PI)/2*n;
const width=map.clientWidth||900,height=map.clientHeight||520;
const horizontal=Math.ceil(width/512)+1,vertical=Math.ceil(height/512)+1;
map.replaceChildren();
for(let dx=-horizontal;dx<=horizontal;dx++)for(let dy=-vertical;dy<=vertical;dy++){{
const rawX=Math.floor(x)+dx,tileY=Math.floor(y)+dy;
if(tileY<0||tileY>=n)continue;
const tileX=((rawX%n)+n)%n;
const image=document.createElement("img");
image.className="map-tile";image.alt="";image.loading="lazy";
image.src=provider.url.replace("{{z}}",zoom).replace("{{x}}",tileX).replace("{{y}}",tileY);
image.style.left=(width/2+(rawX-x)*256)+"px";
image.style.top=(height/2+(tileY-y)*256)+"px";
map.appendChild(image);
}}
const marker=document.createElement("span");marker.className="map-marker";
marker.title=lat.toFixed(5)+", "+lon.toFixed(5);map.appendChild(marker);
document.getElementById("map-attribution").textContent=provider.label;
document.getElementById("geo-map-status").textContent=
"Position centrée : "+lat.toFixed(5)+", "+lon.toFixed(5)+" · zoom "+zoom;
}}
function locateMap(){{
const status=document.getElementById("geo-map-status");
if(!navigator.geolocation){{status.textContent="Géolocalisation non prise en charge.";return;}}
status.textContent="Demande de position au navigateur...";
navigator.geolocation.getCurrentPosition(position=>{{
const lat=position.coords.latitude,lon=position.coords.longitude;
document.getElementById("map-latitude").value=lat.toFixed(5);
document.getElementById("map-longitude").value=lon.toFixed(5);
showGeoMap(lat,lon);
}},error=>status.textContent="Position refusée ou indisponible : "+error.message,
{{enableHighAccuracy:false,timeout:10000,maximumAge:60000}});
}}
const loadingSteps={{
discover:["Validation du réseau privé autorisé","Sélection de Nmap ou du moteur portable",
"Envoi des sondes de découverte","Collecte des hôtes ayant répondu",
"Résolution des noms disponibles","Préparation du résultat"],
scan:["Validation de la cible et des ports","Sélection de Nmap ou du moteur portable",
"Test des ports demandés","Identification des services disponibles",
"Préparation du résultat"],
profile:["Validation de la cible","Collecte des noms et voisins réseau",
"Observation des services","Estimation du type d'appareil",
"Construction de la fiche technique"],
wireless:["Vérification des capacités du système","Interrogation des API locales",
"Normalisation des informations disponibles","Préparation du résultat sans-fil"],
headers:["Ouverture de la connexion HTTP","Lecture des en-têtes exposés",
"Analyse des politiques de sécurité","Préparation des constats"],
tools:["Validation de l'entrée","Lancement de l'analyse locale",
"Classement des observations","Préparation du résultat technique"],
context:["Validation des coordonnées","Interrogation du service météo",
"Lecture des conditions actuelles","Préparation du contexte"],
lab:["Création de l'espace pédagogique","Génération des artefacts inoffensifs",
"Vérification des fichiers du laboratoire"],
settings:["Validation des préférences","Écriture de la configuration locale"],
default:["Validation de la demande","Traitement local en cours","Préparation de la réponse"]
}};
document.querySelectorAll("form").forEach(form=>form.addEventListener("submit",async event=>{{
if(form.dataset.loading==="1")return;
if(form.dataset.confirm&&!window.confirm(form.dataset.confirm)){{event.preventDefault();return;}}
event.preventDefault();
form.dataset.loading="1";
const route=(new URL(form.action)).pathname.split("/").filter(Boolean).pop()||"default";
const action=form.querySelector("[name=action]")?.value||route;
const steps=loadingSteps[action]||loadingSteps[route]||loadingSteps.default;
const overlay=document.getElementById("loading-overlay");
const log=document.getElementById("loading-log");
const timer=document.getElementById("loading-time");
const title=document.getElementById("loading-title");
title.textContent=(route==="recon"?"RECONNAISSANCE":route.toUpperCase())+" EN COURS";
overlay.classList.add("active");
let elapsed=0,index=0;
const addLine=text=>{{const line=document.createElement("span");line.textContent=text;
log.appendChild(line);log.scrollTop=log.scrollHeight;}};
const subject=form.querySelector("[name=subject],[name=target],[name=url]");
if(subject?.value)addLine("Cible déclarée : "+subject.value);
addLine(steps[index++]);
const timerId=setInterval(()=>{{elapsed++;timer.textContent=String(Math.floor(elapsed/60)).padStart(2,"0")
+":"+String(elapsed%60).padStart(2,"0");}},1000);
const logId=setInterval(()=>{{if(index<steps.length)addLine(steps[index++]);
else addLine("Traitement toujours actif depuis "+elapsed+" seconde(s), attente de la réponse...");}},1400);
const started=Date.now();
try{{
const response=await fetch(form.action,{{
method:(form.method||"POST").toUpperCase(),body:new FormData(form),
credentials:"same-origin",redirect:"follow"
}});
const html=await response.text();
const minimum=1200-(Date.now()-started);
if(minimum>0)await new Promise(resolve=>setTimeout(resolve,minimum));
clearInterval(timerId);clearInterval(logId);
addLine("Réponse reçue, affichage du résultat...");
const destination=new URL(response.url||form.action);
history.replaceState({{}},"",destination.pathname+destination.search);
document.open();document.write(html);document.close();
}}catch(error){{
clearInterval(timerId);clearInterval(logId);
addLine("Le chargement dynamique a échoué, envoi classique...");
form.submit();
}}
}}));
</script></body></html>"""


class ToolboxHandler(BaseHTTPRequestHandler):
    server_version = "CyberToolboxGUI/2.13"

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
            "/operations": self._operations,
            "/profile": self._profile,
            "/recon": self._recon,
            "/headers": self._headers,
            "/lab": self._lab,
            "/wireless": self._wireless,
            "/exposure": self._exposure,
            "/map": self._map,
            "/context": self._context,
            "/tools": self._tools,
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
            "/recon": lambda: self._run_recon(data),
            "/headers": lambda: self._run_headers(data),
            "/lab": self._prepare_lab,
            "/wireless": lambda: self._run_wireless(data),
            "/context": lambda: self._run_context(data),
            "/tools": lambda: self._run_tools(data),
            "/data": lambda: self._run_data(data),
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
        exposure = exposure_inventory()
        history_count = len(list_history())
        body = f"""<div class="grid"><section class="card wide">
<span class="eyebrow">Main operation</span><h2>Cyber Learning Console</h2>
<p>Une interface commune au téléphone et au PC : opérations, reconnaissance,
laboratoires, données et restitution.</p><a class="button" href="/recon">LANCER UNE RECON</a>
</section><section class="card"><span class="eyebrow">Réseau local</span>
<div class="metric">{exposure['asset_count']:02d}</div><p>actifs indexés</p>
<span class="badge">{exposure['service_count']} services</span></section>
<section class="card full"><div class="group-label">Applications</div>
<div class="app-grid">
<a class="app" href="/operations"><strong>Operations</strong><span>Parcours guidés</span></a>
<a class="app" href="/recon"><strong>Recon</strong><span>Découverte et ports</span></a>
<a class="app" href="/profile"><strong>Profiler</strong><span>Actifs et confiance</span></a>
<a class="app" href="/lab"><strong>Labs</strong><span>Journaux, HTTP, secrets</span></a>
<a class="app" href="/wireless"><strong>Sans-fil</strong><span>Wi-Fi, Bluetooth, WPA2</span></a>
<a class="app" href="/exposure"><strong>Exposure</strong><span>Vue locale type Shodan</span></a>
<a class="app" href="/map"><strong>Cartographie</strong><span>Position et topologie réseau</span></a>
<a class="app" href="/reports"><strong>Archives</strong>
<span>{history_count} historiques / {len(list_reports())} rapports</span></a>
<a class="app" href="/tools"><strong>Tools</strong><span>Système, hash, DNS, TLS</span></a>
<a class="app" href="/context"><strong>Context</strong><span>Heure, fuseau, météo</span></a>
</div></section><section class="card full"><h2>Configuration active</h2>
{_value(dict(settings_summary(settings)))}</section></div>"""
        self._send(render_layout("Tableau de bord", body))

    def _accept(self, data: dict[str, list[str]]) -> None:
        if _checked(data, "accepted"):
            self.state.accepted = True
        self._redirect("/")

    def _operations(self) -> None:
        body = """<div class="grid"><section class="card wide">
<span class="eyebrow">Guided operations</span><h2>Choisir un parcours</h2>
<p>Les opérations relient plusieurs modules dans un ordre compréhensible.
Chaque étape explique l'objectif, la preuve obtenue et la suite logique.</p>
<div class="app-grid">
<a class="app" href="/lab"><strong>Signal fantôme</strong>
<span>Journaux, payload factice et script risqué</span></a>
<a class="app" href="/recon"><strong>Mission réseau</strong>
<span>Découverte, cible, ports et conservation</span></a>
<a class="app" href="/profile"><strong>Profil autorisé</strong>
<span>Nom, type probable, services et confiance</span></a>
</div></section><section class="card"><h2>Mode d'emploi</h2>
<ol><li>Définir le périmètre autorisé.</li><li>Collecter une preuve.</li>
<li>Interpréter sans surévaluer le résultat.</li><li>Conserver ou produire un rapport.</li></ol>
<p class="muted">Le scénario Watchdog interactif complet reste aussi disponible
dans le terminal avec <code>run.bat watchdog</code>.</p></section></div>"""
        self._send(render_layout("Opérations guidées", body))

    def _recon(self) -> None:
        settings = load_settings()
        body = f"""<div class="grid"><section class="card wide"><h2>Recon autorisée</h2>
<p class="muted">Découverte d'un réseau privé ou scan des ports d'une cible.
Les résultats conservés alimentent la carte et l'index d'exposition local.</p>
<form method="post" action="/recon">{self._token()}
<label>Action<select name="action"><option value="discover">Découvrir les hôtes</option>
<option value="scan">Scanner les ports</option></select></label>
<label>Réseau ou cible<input name="subject" placeholder="192.168.1.0/24 ou 192.168.1.25" required></label>
<label>Ports<input name="ports" value="{escape(settings.default_ports)}"></label>
<label class="check"><input type="checkbox" name="authorized" required>
Je confirme disposer de l'autorisation sur ce périmètre.</label>
<label class="check"><input type="checkbox" name="keep" checked>
Conserver dans l'historique local.</label>
<button type="submit">EXÉCUTER LA RECON</button></form></section>
<section class="card"><h2>Parcours</h2><ul class="clean"><li>Découvrir</li>
<li>Sélectionner un actif</li><li>Scanner ses ports</li>
<li>Profiler et interpréter</li></ul>
<a href="/headers">Ouvrir l'audit HTTP passif</a></section>
{self._result("/recon")}</div>"""
        self._send(render_layout("Reconnaissance", body))

    def _run_recon(self, data: dict[str, list[str]]) -> None:
        self._clear()
        started = time.monotonic()
        try:
            if not _checked(data, "authorized"):
                raise ValueError("L'autorisation explicite est obligatoire.")
            settings = load_settings()
            action = _field(data, "action")
            subject = _field(data, "subject")
            ports = ""
            if action == "discover":
                results, engine = discover_hosts(subject, settings.prefer_nmap)
                kind = "discovery"
            elif action == "scan":
                from .safety import parse_ports

                ports = _field(data, "ports", settings.default_ports)
                results, engine = scan_ports(
                    subject,
                    parse_ports(ports),
                    settings.scan_timeout,
                    settings.prefer_nmap,
                )
                kind = "port_scan"
            else:
                raise ValueError("Action de reconnaissance inconnue.")
            result: dict[str, Any] = {
                "action": action,
                "subject": subject,
                "engine": engine,
                "duration_seconds": round(time.monotonic() - started, 2),
                "results": results,
            }
            if _checked(data, "keep"):
                result["history"] = str(
                    save_history(kind, subject, engine, results, ports=ports)
                )
            self.state.result_title = "Résultat de reconnaissance"
            self.state.result_route = "/recon"
            self.state.result = result
        except (ValueError, OSError) as exc:
            self.state.error = str(exc)
        self._redirect("/recon")

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
        feedback = ""
        if self.state.message:
            feedback = f'<div class="notice">{escape(self.state.message)}</div>'
            self.state.message = ""
        elif self.state.error:
            feedback = f'<div class="notice error">{escape(self.state.error)}</div>'
            self.state.error = ""

        def actions(scope: str, name: str, current_label: str) -> str:
            return f"""<div class="data-actions">
<form method="post" action="/data">{self._token()}
<input type="hidden" name="scope" value="{scope}">
<input type="hidden" name="name" value="{escape(name)}">
<input type="hidden" name="operation" value="rename">
<label>Nouveau nom<input name="new_name" value="{escape(current_label)}" required></label>
<button type="submit">RENOMMER</button></form>
<form class="compact" method="post" action="/data"
data-confirm="Supprimer définitivement cet élément ?">{self._token()}
<input type="hidden" name="scope" value="{scope}">
<input type="hidden" name="name" value="{escape(name)}">
<input type="hidden" name="operation" value="delete">
<button class="danger" type="submit">SUPPRIMER</button></form></div>"""

        report_items = "".join(
            f"""<li><strong><a href="/report?name={quote(path.name)}">
{escape(path.name)}</a></strong>{actions("report", path.name, path.stem)}</li>"""
            for path in list_reports()
        ) or "<li class='muted'>Aucun rapport disponible.</li>"

        history_items = []
        for path in list_history():
            payload = load_history(path)
            history_items.append(
                f"""<li><strong>{escape(history_display_name(payload))}</strong>
<span class="muted"> · {escape(str(payload.get("kind", "")))}</span>
{actions("history", path.name, str(payload.get("label", "")))}</li>"""
            )
        histories = "".join(history_items) or "<li class='muted'>Aucun historique disponible.</li>"

        mission_items = "".join(
            f"<li><strong>{escape(path.stem)}</strong>{actions('mission', path.name, path.stem)}</li>"
            for path in list_missions()
        ) or "<li class='muted'>Aucune mission sauvegardée.</li>"

        delete_all = f"""<form method="post" action="/data"
data-confirm="Supprimer tous les rapports, historiques et missions ? Cette action est irréversible.">
{self._token()}<input type="hidden" name="scope" value="all">
<input type="hidden" name="operation" value="delete_all">
<button class="danger" type="submit">TOUT SUPPRIMER</button></form>"""
        body = f"""{feedback}<section class="card full" data-tabs>
<h2>Données locales</h2><p class="muted">Consultez, renommez ou supprimez les
éléments stockés par la toolbox.</p><div class="tabs">
<button class="tab-button active" type="button" data-tab="reports">Rapports</button>
<button class="tab-button" type="button" data-tab="history">Historiques</button>
<button class="tab-button" type="button" data-tab="missions">Missions</button>
<button class="tab-button" type="button" data-tab="cleanup">Nettoyage</button></div>
<div class="tab-panel active" data-panel="reports"><ul class="clean">{report_items}</ul></div>
<div class="tab-panel" data-panel="history"><ul class="clean">{histories}</ul></div>
<div class="tab-panel" data-panel="missions"><ul class="clean">{mission_items}</ul></div>
<div class="tab-panel" data-panel="cleanup"><div class="notice error">
Cette action efface toutes les données générées, mais pas le code du projet.</div>
{delete_all}</div></section>"""
        self._send(render_layout("Données", body))

    def _run_data(self, data: dict[str, list[str]]) -> None:
        self.state.message = ""
        self.state.error = ""
        scope = _field(data, "scope")
        operation = _field(data, "operation")
        name = _field(data, "name")
        try:
            if operation == "delete_all" and scope == "all":
                histories = delete_all_history()
                reports = delete_all_reports()
                missions = delete_all_missions()
                self.state.message = (
                    f"{histories} historique(s), {reports} rapport(s) et "
                    f"{missions} mission(s) supprimé(s)."
                )
            elif scope == "report":
                path = self._stored_path(list_reports(), name)
                if operation == "rename":
                    renamed = rename_report(path, _field(data, "new_name"))
                    self.state.message = f"Rapport renommé : {renamed.name}"
                elif operation == "delete":
                    delete_report(path)
                    self.state.message = "Rapport supprimé."
                else:
                    raise ValueError("Action de rapport inconnue.")
            elif scope == "history":
                path = self._stored_path(list_history(), name)
                if operation == "rename":
                    rename_history(path, _field(data, "new_name"))
                    self.state.message = "Historique renommé."
                elif operation == "delete":
                    delete_history(path)
                    self.state.message = "Historique supprimé."
                else:
                    raise ValueError("Action d'historique inconnue.")
            elif scope == "mission":
                path = self._stored_path(list_missions(), name)
                if operation == "rename":
                    renamed = rename_mission(path, _field(data, "new_name"))
                    self.state.message = f"Mission renommée : {renamed.name}"
                elif operation == "delete":
                    delete_mission(path)
                    self.state.message = "Mission supprimée."
                else:
                    raise ValueError("Action de mission inconnue.")
            else:
                raise ValueError("Type de donnée inconnu.")
        except (ValueError, OSError) as exc:
            self.state.error = str(exc)
        self._redirect("/reports")

    @staticmethod
    def _stored_path(paths: list[Path], name: str) -> Path:
        path = next((item for item in paths if item.name == name), None)
        if path is None:
            raise ValueError("Élément enregistré introuvable.")
        return path

    def _exposure(self) -> None:
        inventory = exposure_inventory()
        body = f"""<div class="grid"><section class="card full">
<span class="eyebrow">Local exposure index</span><h2>Vue type Shodan</h2>
<div class="notice">Aucune recherche Internet : cette page indexe uniquement les
scans privés explicitement autorisés et conservés localement.</div>
{_value(inventory)}</section></div>"""
        self._send(render_layout("Exposition locale", body))

    def _map(self) -> None:
        body = f"""<div class="grid"><section class="card full" data-tabs>
<span class="eyebrow">Map console</span><h2>Cartographie</h2>
<div class="tabs"><button class="tab-button active" type="button"
data-tab="geo">Carte géographique</button><button class="tab-button" type="button"
data-tab="network">Topologie réseau</button></div>
<div class="tab-panel active" data-panel="geo">
<div class="notice">La position est facultative, demandée par le navigateur et
non enregistrée. Les appareils découverts sur le réseau ne sont jamais placés
sur cette carte géographique.</div>
<div class="map-controls"><input id="map-latitude" type="number" step="any"
placeholder="Latitude"><input id="map-longitude" type="number" step="any"
placeholder="Longitude"><select id="map-layer" aria-label="Fond de carte">
<option value="standard">Standard</option>
<option value="humanitarian">Humanitaire</option>
<option value="cycle">Cyclable</option>
<option value="topographic">Topographique / relief</option>
</select><select id="map-zoom" aria-label="Niveau de zoom">
<option value="12">Zoom régional</option><option value="14">Zoom ville</option>
<option value="16" selected>Zoom quartier</option><option value="18">Zoom rue</option>
</select><button type="button"
onclick="showGeoMap(document.getElementById('map-latitude').value,
document.getElementById('map-longitude').value)">AFFICHER</button></div>
<button type="button" onclick="locateMap()">UTILISER MA POSITION</button>
<p id="geo-map-status" class="muted">Aucune position demandée.</p>
<div class="geo-map" id="geo-map-frame" role="img"
aria-label="Carte centrée sur la position choisie"></div>
<p class="muted">Fond actif : <span id="map-attribution">aucun</span>. Données ©
<a href="https://www.openstreetmap.org/copyright" target="_blank"
rel="noreferrer">contributeurs OpenStreetMap</a>. OpenStreetMap ne fournit pas
de vue satellite native ; une telle vue nécessiterait un fournisseur d'imagerie
distinct et ses propres conditions d'utilisation. Styles complémentaires :
<a href="https://www.hotosm.org/" target="_blank" rel="noreferrer">HOT</a>,
<a href="https://www.cyclosm.org/" target="_blank" rel="noreferrer">CyclOSM</a>
et <a href="https://opentopomap.org/" target="_blank"
rel="noreferrer">OpenTopoMap</a>.</p></div>
<div class="tab-panel" data-panel="network">{render_topology()}
<p class="muted">Vert : actif observé. Orange : service à vérifier. Cette vue
est une topologie technique schématique, sans localisation physique.</p></div>
</section></div>"""
        self._send(render_layout("Cartographie", body))

    def _context(self) -> None:
        body = f"""<div class="grid"><section class="card wide"><h2>Contexte local</h2>
{_value(local_context())}<p class="muted">L'heure et le fuseau sont lus localement.
La météo nécessite des coordonnées consenties et une connexion Internet.</p></section>
<section class="card"><h2>Météo</h2><form method="post" action="/context">
{self._token()}<label>Latitude<input name="latitude" type="number" step="any" required></label>
<label>Longitude<input name="longitude" type="number" step="any" required></label>
<button type="button" onclick="locate()">UTILISER MA POSITION</button>
<button type="submit">CHARGER LA MÉTÉO</button></form></section>
{self._result("/context")}</div>"""
        self._send(render_layout("Heure, zone et météo", body))

    def _run_context(self, data: dict[str, list[str]]) -> None:
        self._clear()
        try:
            self.state.result_title = "Météo actuelle"
            self.state.result_route = "/context"
            self.state.result = weather_for_coordinates(
                float(_field(data, "latitude")),
                float(_field(data, "longitude")),
            )
        except (ValueError, OSError) as exc:
            self.state.error = str(exc)
        self._redirect("/context")

    def _tools(self) -> None:
        body = f"""<div class="grid"><section class="card wide"><h2>Outils techniques</h2>
<form method="post" action="/tools">{self._token()}
<label>Action<select name="action"><option value="system">Audit du système local</option>
<option value="hash">Hash SHA-256 d'un texte</option><option value="dns">Résolution DNS</option>
<option value="tls">Inspection TLS</option><option value="config">Configuration locale</option>
<option value="permissions">Permissions d'un chemin</option>
<option value="log">Analyser un journal</option>
<option value="script">Analyser un script</option>
<option value="payload">Analyser un payload factice</option>
<option value="password">Évaluer un mot de passe local</option>
<option value="b64encode">Encoder en Base64</option>
<option value="b64decode">Décoder du Base64</option></select></label>
<label>Valeur ou chemin<input name="value"
placeholder="Texte, domaine ou chemin relatif, ex. lab_workspace/suspicious.log"></label>
<button type="submit">EXÉCUTER</button></form></section>
<section class="card"><h2>Limite des fichiers</h2><p class="muted">
Pour protéger l'appareil, le GUI analyse uniquement les fichiers présents dans
le dossier de la toolbox. Les chemins absolus extérieurs sont refusés.</p>
<a href="/lab">Préparer les artefacts du laboratoire</a></section>
{self._result("/tools")}</div>"""
        self._send(render_layout("Outils", body))

    def _run_tools(self, data: dict[str, list[str]]) -> None:
        self._clear()
        try:
            action = _field(data, "action")
            value = _field(data, "value")
            if action == "system":
                result: Any = dict(audit_system())
            elif action == "hash":
                result = {"algorithm": "sha256", "digest": hash_text(value)}
            elif action == "dns":
                result = dns_lookup(value)
            elif action == "tls":
                result = inspect_tls(value)
            elif action == "config":
                result = audit_local_configuration()
            elif action == "permissions":
                result = audit_path(_workspace_path(value))
            elif action == "log":
                result = analyze_log(_workspace_path(value))
            elif action == "script":
                result = analyze_script(_workspace_path(value))
            elif action == "payload":
                result = analyze_payload_file(_workspace_path(value))
            elif action == "password":
                result = analyze_password(value)
            elif action == "b64encode":
                result = {"encoded": base64_encode(value)}
            elif action == "b64decode":
                result = {"decoded": base64_decode(value)}
            else:
                raise ValueError("Outil inconnu.")
            self.state.result_title = "Résultat technique"
            self.state.result_route = "/tools"
            self.state.result = result
        except (ValueError, OSError) as exc:
            self.state.error = str(exc)
        self._redirect("/tools")

    def _wireless(self) -> None:
        body = f"""<div class="grid"><section class="card full" data-tabs>
<h2>Environnement sans-fil</h2><p class="muted">Toutes les collectes utilisent
les API autorisées du système. Aucun appairage, connexion, capture ou paquet de
désauthentification n'est émis.</p>
<div class="tabs"><button class="tab-button active" type="button"
data-tab="scan">Inventaire</button><button class="tab-button" type="button"
data-tab="wpa">Lab WPA2</button></div>
<div class="tab-panel active" data-panel="scan"><form method="post" action="/wireless">
{self._token()}<label>Action<select name="action">
<option value="wifi">Réseaux Wi-Fi visibles</option>
<option value="bluetooth">Bluetooth connu ou visible</option>
<option value="carrier">Opérateur mobile de cet appareil</option>
<option value="environment">Profil de l'appareil courant</option>
<option value="diagnostic">Diagnostic des capacités</option>
</select></label><button type="submit">EXÉCUTER</button></form>
<div class="notice">Sous Windows, la liste complète des réseaux voisins nécessite
l'autorisation de localisation pour les applications de bureau. Sans elle, seul
le réseau connecté peut être disponible.<br><br>
Sur Android, le scan fonctionne dans Termux avec l'application Termux:API,
le paquet <code>termux-api</code> et les permissions Localisation/Appareils à
proximité. L'opérateur mobile n'est lisible que pour le téléphone qui exécute
la toolbox, jamais pour un appareil tiers observé en Wi-Fi ou Bluetooth.</div></div>
<div class="tab-panel" data-panel="wpa"><h2>Lab WPA2 hors ligne</h2>
<form method="post" action="/wireless">{self._token()}
<input type="hidden" name="action" value="wifi_lab">
<label>SSID fictif<input name="ssid" value="CTOS-LAB" required></label>
<label>Mot de passe temporaire<input type="password" name="secret" required></label>
<label>Candidats, un par ligne<textarea name="candidates" rows="6"
required>motdepasse
classe-2026
password</textarea></label>
<button type="submit">TESTER HORS LIGNE</button></form></div></section>
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
            elif action == "carrier":
                result = mobile_operator_info()
            elif action == "environment":
                result = {
                    "identity": local_device_identity(),
                    "wifi": wifi_scan(),
                    "bluetooth": bluetooth_inventory(),
                    "mobile_operator": mobile_operator_info(),
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
        themes = (
            ("violet", "Violet", "#d600a9"),
            ("github", "Bleu GitHub", "#58a6ff"),
            ("terminal", "Vert terminal", "#39ff88"),
            ("ocean", "Bleu océan", "#00c8ff"),
            ("amber", "Ambre", "#ffad22"),
        )
        theme_choices = "".join(
            f'<label class="theme-choice"><input type="radio" name="theme" '
            f'value="{key}"{" checked" if settings.theme == key else ""}>'
            f'<span class="theme-swatch"><strong style="color:{color}">● {label}</strong>'
            "</span></label>"
            for key, label, color in themes
        )
        body = f"""{feedback}<section class="card full" data-tabs>
<h2>Préférences locales</h2>
<form method="post" action="/settings">{self._token()}
<div class="tabs"><button class="tab-button active" type="button"
data-tab="appearance">Apparence</button><button class="tab-button" type="button"
data-tab="behavior">Comportement</button><button class="tab-button" type="button"
data-tab="network">Réseau</button></div>
<div class="tab-panel active" data-panel="appearance"><div class="theme-grid">
{theme_choices}</div>
<label class="switch"><span><strong>Glassmorphism</strong><br>
<span class="muted">Transparence et flou des panneaux</span></span>
<input type="checkbox" name="glass_effect"{" checked" if settings.glass_effect else ""}>
<span class="switch-track"></span></label></div>
<div class="tab-panel" data-panel="behavior">
<label>Langue<select name="language">
<option value="fr"{" selected" if settings.language == "fr" else ""}>Français</option>
<option value="en"{" selected" if settings.language == "en" else ""}>English</option>
</select></label><label>Rapports<select name="report_mode">
<option value="ask"{" selected" if settings.report_mode == "ask" else ""}>Demander</option>
<option value="auto"{" selected" if settings.report_mode == "auto" else ""}>Automatique</option>
<option value="off"{" selected" if settings.report_mode == "off" else ""}>Désactivé</option>
</select></label>
<label class="switch"><span>Afficher les explications</span>
<input type="checkbox" name="show_lessons"{" checked" if settings.show_lessons else ""}>
<span class="switch-track"></span></label></div>
<div class="tab-panel" data-panel="network"><label>Ports par défaut
<input name="default_ports" value="{escape(settings.default_ports)}"></label>
<label>Délai TCP<input type="number" step="0.1" min="0.1" max="5"
name="scan_timeout" value="{settings.scan_timeout}"></label>
<label class="switch"><span>Préférer Nmap</span>
<input type="checkbox" name="prefer_nmap"{" checked" if settings.prefer_nmap else ""}>
<span class="switch-track"></span></label>
<label class="switch"><span>Autoriser la corrélation DNS</span>
<input type="checkbox" name="internet_correlation"{" checked" if settings.internet_correlation else ""}>
<span class="switch-track"></span></label></div>
<button type="submit">ENREGISTRER</button></form></section>"""
        self._send(render_layout("Paramètres", body))

    def _save_settings(self, data: dict[str, list[str]]) -> None:
        try:
            settings = Settings(
                language=_field(data, "language", "fr"),
                report_mode=_field(data, "report_mode", "ask"),
                theme=_field(data, "theme", "violet"),
                glass_effect=_checked(data, "glass_effect"),
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
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "img-src 'self' data: https://tile.openstreetmap.org "
            "https://*.tile.openstreetmap.fr https://*.tile.opentopomap.org; "
            "frame-src https://www.openstreetmap.org",
        )
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

from __future__ import annotations

from dataclasses import asdict
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import socket
import time
from datetime import datetime
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
from .labs.network import discover_hosts, local_ipv4_network, scan_ports
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
from .records import (
    Artifact,
    TimelineEvent,
    delete_all_records,
    delete_record,
    list_records,
    load_record,
    record_display_name,
    records_summary,
    save_record,
    save_recon_records,
)
from .settings import Settings, load_settings, save_settings, settings_summary


PROJECT_ROOT = Path(__file__).resolve().parent.parent

CSS = """
:root{color-scheme:dark;--bg:#030609;--panel-rgb:8,12,15;--solid-panel:#0b1117;
--glass-alpha:.46;--panel:rgba(var(--panel-rgb),var(--glass-alpha));
--line:rgba(104,255,106,.28);--signal:#79ff3d;--accent:#38e8ff;
--text:#f4f7fb;--muted:#b7c3d1;--danger:#ff4d59;--orange:#ff8a22;
--glow:rgba(121,255,61,.16);--field:rgba(1,8,7,.52);--radius:8px}
body[data-theme="core"]{--bg:#030609;--panel-rgb:8,12,15;
--signal:#79ff3d;--accent:#38e8ff;--glow:rgba(121,255,61,.16);--field:rgba(1,8,7,.52)}
body[data-theme="github"]{--bg:#0d1117;--panel-rgb:22,27,34;
--signal:#58a6ff;--accent:#79c0ff;--glow:rgba(88,166,255,.2);--field:rgba(13,17,23,.78)}
body[data-theme="violet"]{--bg:#050506;--panel-rgb:13,13,15;
--signal:#d600a9;--accent:#51d414;--glow:rgba(214,0,169,.18);--field:rgba(7,16,13,.72)}
body[data-theme="terminal"]{--bg:#020805;--panel-rgb:4,20,12;
--signal:#39ff88;--accent:#b6ff3b;--glow:rgba(57,255,136,.18);--field:rgba(2,14,8,.8)}
body[data-theme="ocean"]{--bg:#06121b;--panel-rgb:8,31,45;
--signal:#00c8ff;--accent:#00ffd0;--glow:rgba(0,200,255,.2);--field:rgba(4,24,35,.8)}
body[data-theme="amber"]{--bg:#110b03;--panel-rgb:32,21,7;
--signal:#ffad22;--accent:#ffe066;--glow:rgba(255,173,34,.2);--field:rgba(25,15,4,.8)}
body[data-app-mode="light"]{color-scheme:light;--bg:#f8fafc;--panel-rgb:255,255,255;--solid-panel:#ffffff;
--text:#111827;--muted:#475569;--line:rgba(15,23,42,.16);--field:rgba(255,255,255,.82);
--signal:#15803d;--accent:#0284c7;--glow:rgba(21,128,61,.12)}
body[data-app-mode="light"]:before{color:rgba(2,132,199,.055)}
body[data-app-mode="light"] .context-bar{background:rgba(255,255,255,.72);color:#166534}
body[data-app-mode="light"] .card,body[data-app-mode="light"] .sidebar,
body[data-app-mode="light"] input,body[data-app-mode="light"] select,body[data-app-mode="light"] textarea,
body[data-app-mode="light"] .tab-button,body[data-app-mode="light"] .theme-swatch,
body[data-app-mode="light"] .notice,body[data-app-mode="light"] .badge{box-shadow:inset 0 1px 0 rgba(255,255,255,.7),0 12px 32px rgba(15,23,42,.08)}
body[data-app-mode="light"] pre,body[data-app-mode="light"] .loading-log{background:rgba(255,255,255,.82);color:#0f172a}
body[data-app-mode="light"] .sc-wordmark{color:#111827;text-shadow:none}
body[data-app-mode="light"] .sc-mark{border-color:#111827}
body.no-glass{--panel:var(--solid-panel);--field:var(--solid-panel)}
*{box-sizing:border-box}html{background:var(--bg)}body{min-height:100vh;margin:0;
color:var(--text);font:15px/1.55 "Cascadia Code","JetBrains Mono",Consolas,monospace;
background:linear-gradient(rgba(121,255,61,.04) 1px,transparent 1px),
linear-gradient(90deg,rgba(56,232,255,.028) 1px,transparent 1px),
repeating-linear-gradient(90deg,rgba(255,138,34,.045) 0 1px,transparent 1px 78px),
var(--bg);background-size:30px 30px,30px 30px,auto,auto}
body:before{content:"01001101 00110101 1010";position:fixed;inset:0;pointer-events:none;
padding:18px;color:rgba(121,255,61,.09);font-size:10px;line-height:1.35;
letter-spacing:.6em;word-spacing:1.4em;overflow:hidden;opacity:.9}
body:after{content:"";position:fixed;inset:0;pointer-events:none;background:
repeating-linear-gradient(0deg,transparent 0 3px,rgba(255,255,255,.018) 4px)}
a{color:var(--signal);text-decoration:none}
a:hover{color:var(--accent)}.shell{min-height:100vh;display:grid;
grid-template-columns:minmax(0,1fr)}
.sidebar{position:fixed;left:18px;top:18px;width:250px;height:calc(100vh - 36px);
padding:24px 18px;border:1px solid var(--line);background:var(--panel);
backdrop-filter:blur(30px) saturate(150%);box-shadow:0 20px 70px rgba(0,0,0,.44);
transition:transform .25s ease,opacity .2s ease;z-index:20;overflow-y:auto;overflow-x:hidden;
scrollbar-color:var(--signal) transparent}.shell.nav-collapsed .sidebar{
transform:translateX(-102%);opacity:0;pointer-events:none}
.brand{margin-bottom:30px;letter-spacing:.08em}.brand strong{display:block;
color:var(--signal);font-size:18px}.brand small,.muted,.eyebrow{color:var(--muted)}
.sc-wordmark{display:flex;align-items:center;gap:9px;color:#fff;font-size:28px;
font-weight:800;letter-spacing:.14em;text-shadow:0 0 18px rgba(255,255,255,.24)}
.sc-mark{display:inline-block;width:18px;height:23px;border:2px solid #fff;
border-radius:14px 14px 14px 3px;transform:rotate(45deg);box-shadow:0 0 18px var(--glow)}
.brand small{display:block;margin-top:8px;color:var(--signal)}
.status{display:flex;gap:8px;align-items:center;margin-top:10px;font-size:11px}
.pulse{width:8px;height:8px;border-radius:50%;background:var(--signal);
box-shadow:0 0 12px var(--signal);animation:pulse 1.8s infinite}
@keyframes pulse{50%{opacity:.35}}nav{display:grid;gap:4px}nav a{padding:9px 10px;
color:var(--muted);border-left:2px solid transparent;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
nav a:hover{color:var(--text);
border-color:var(--signal);background:rgba(121,255,61,.08)}main{min-width:0;
padding:72px clamp(18px,4vw,54px) 60px;transition:padding-left .25s ease}.shell:not(.nav-collapsed) main{
padding-left:calc(286px + clamp(18px,4vw,54px))}.topline{display:flex;justify-content:
space-between;gap:16px;align-items:baseline;border-bottom:1px solid var(--line);
margin-bottom:28px;padding-left:58px;min-height:44px}h1{margin:0 0 12px;font-size:clamp(24px,4vw,42px);
letter-spacing:-.04em}h1:before{content:"// ";color:var(--signal)}h2{color:
var(--signal);font-size:16px;letter-spacing:.06em;text-transform:uppercase}
.eyebrow{text-transform:uppercase;letter-spacing:.16em;font-size:11px}.grid{display:
grid;grid-template-columns:repeat(12,1fr);gap:16px}.card{grid-column:span 4;
position:relative;overflow:hidden;padding:20px;border:1px solid var(--line);
background:var(--panel);backdrop-filter:blur(32px) saturate(155%);
box-shadow:inset 0 1px 0 rgba(255,255,255,.08),0 18px 54px rgba(0,0,0,.42),0 0 28px var(--glow)}
.no-glass .card,.no-glass .sidebar,
.no-glass .loading-panel,.no-glass input,.no-glass select,.no-glass textarea,
.no-glass .app,.no-glass .notice,.no-glass .tab-button,.no-glass .theme-swatch,
.no-glass .badge,.no-glass pre{backdrop-filter:none}.card:before{
content:"";position:absolute;width:70px;height:1px;right:0;top:0;background:
var(--signal);box-shadow:0 0 12px var(--signal)}.card.wide{grid-column:span 8}
.card.full{grid-column:1/-1}.metric{color:var(--accent);font-size:30px;font-weight:700}
.app-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(112px,1fr));gap:14px;align-items:start}
.app{min-height:142px;padding:12px;border:1px solid transparent;background:transparent;
display:grid;justify-items:center;align-content:start;gap:8px;text-align:center}
.app:before{content:attr(data-icon);display:grid;place-items:center;width:66px;height:66px;
border:1px solid var(--line);border-radius:50%;background:var(--panel);backdrop-filter:blur(24px) saturate(145%);
color:var(--muted);font-weight:900;font-size:14px;letter-spacing:.02em}
.app strong{color:var(--text);font-size:13px}
.app span{color:var(--muted);font-size:11px;line-height:1.35}.app:hover:before{border-color:var(--signal);
color:#03100a;background:var(--signal)}
.app:hover strong{color:var(--signal)}.app:hover{
box-shadow:0 0 22px var(--glow)}.group-label{margin:22px 0 8px;color:var(--signal);
letter-spacing:.12em;font-size:11px;text-transform:uppercase}.context-bar{display:flex;
gap:18px;flex-wrap:wrap;padding:10px 14px;background:rgba(121,255,61,.1);
border:1px solid var(--line);color:var(--signal);font-weight:700}
.map{width:100%;min-height:430px;border:1px solid var(--line);background:#09090b}
.node{fill:#18181c;stroke:var(--accent);stroke-width:2}.node-risk{stroke:var(--orange)}
.edge{stroke:#5c5c62;stroke-width:1}.map-label{fill:#eee;font-size:12px}
.badge{display:inline-block;padding:3px 7px;border:1px solid var(--line);background:var(--panel);
backdrop-filter:blur(14px) saturate(130%);font-size:11px}
.menu-toggle{position:fixed;left:22px;top:18px;z-index:40;width:44px;height:40px;padding:0;
display:grid;place-items:center;font-size:22px;clip-path:none;background:var(--panel);
backdrop-filter:blur(18px);color:var(--text);box-shadow:0 8px 28px rgba(0,0,0,.28)}
.shell:not(.nav-collapsed) .menu-toggle{left:286px}.button,button{display:inline-block;border:1px solid var(--signal);padding:10px 15px;
color:#03100a;background:var(--signal);font:inherit;font-weight:700;cursor:pointer;
clip-path:polygon(0 0,calc(100% - 8px) 0,100% 8px,100% 100%,0 100%)}
.button:hover,button:hover{background:var(--accent);color:#03100a}form{display:grid;
gap:14px}label{display:grid;gap:6px;color:var(--muted)}input,select,textarea{width:100%;
border:1px solid var(--line);background:var(--panel);backdrop-filter:blur(18px) saturate(130%);
color:var(--text);padding:11px 12px;
font:inherit;outline:none}input:focus,select:focus,textarea:focus{border-color:var(--signal)}
input[type=checkbox]{width:auto;accent-color:var(--signal)}.check{display:flex;
align-items:flex-start;gap:9px}.notice{padding:13px 15px;border-left:3px solid
var(--signal);background:var(--panel);backdrop-filter:blur(18px) saturate(130%);margin-bottom:16px}.error{border-color:
var(--danger);color:#ffdce1}.table-wrap{width:100%;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:10px;border-bottom:1px solid var(--line);text-align:left;
vertical-align:top}th{color:var(--signal)}.key-table>tbody>tr>th{width:28%;
min-width:150px}.data-table{min-width:520px}.data-table>thead>tr>th{white-space:nowrap;
background:var(--panel)}.data-table>tbody>tr:nth-child(even){background:rgba(var(--panel-rgb),calc(var(--glass-alpha) + .08))}
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
background:var(--panel);backdrop-filter:blur(14px) saturate(130%);color:var(--muted);clip-path:none;border-color:var(--line)}
.tab-button.active{color:#050506;background:var(--signal);border-color:var(--signal)}
.tab-panel{display:none}.tab-panel.active{display:block}.switch{display:flex;
align-items:center;justify-content:space-between;gap:16px;padding:12px 0;
border-bottom:1px solid var(--line)}.switch input{position:absolute;opacity:0}
.switch-track{width:62px;height:32px;padding:3px;border-radius:999px;background:#3a3a40;
position:relative;transition:.2s}.switch-track:before{content:"☼";position:absolute;right:9px;top:5px;
font-size:14px;color:#fff}.switch-track:after{content:"";display:block;width:26px;height:26px;
border-radius:50%;background:#fff;transition:.2s;box-shadow:0 1px 7px rgba(0,0,0,.28)}
.switch input:checked+.switch-track{background:#1f2937}.switch input:checked+.switch-track:before{
content:"☾";left:11px;right:auto}.switch input:checked+.switch-track:after{transform:translateX(30px)}
.range-row{display:grid;grid-template-columns:1fr auto;gap:12px;align-items:center}
.range-row input{padding:0;accent-color:var(--signal)}
.switch-track{background:#64748b}.switch-track:before{content:"OFF";right:8px;top:7px;
font-size:10px;color:#fff;font-weight:800}.switch input:checked+.switch-track{background:var(--signal)}
.switch input:checked+.switch-track:before{content:"ON";left:10px;right:auto;color:#03100a}
.mode-slider{display:grid;gap:8px;margin:10px 0 14px}
.mode-slider legend{color:var(--muted);padding:0}
.mode-track{position:relative;display:grid;grid-template-columns:repeat(3,1fr);gap:4px;
padding:4px;border:1px solid var(--line);border-radius:999px;background:var(--panel);
backdrop-filter:blur(18px) saturate(130%);overflow:hidden}
.mode-track input{position:absolute;opacity:0;pointer-events:none}
.mode-track span{position:relative;z-index:2;display:grid;place-items:center;min-height:34px;
border-radius:999px;color:var(--muted);font-size:12px;font-weight:700;cursor:pointer}
.mode-track:before{content:"";position:absolute;z-index:1;top:4px;bottom:4px;left:4px;
width:calc((100% - 8px)/3);border-radius:999px;background:var(--signal);
box-shadow:0 0 18px var(--glow);transition:transform .18s ease}
.mode-track[data-value="light"]:before,.mode-track[data-value="day"]:before{transform:translateX(100%)}
.mode-track[data-value="dark"]:before,.mode-track[data-value="night"]:before{transform:translateX(200%)}
.mode-track input:checked+span{color:#06100a}
.theme-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}
.theme-choice{position:relative}.theme-choice input{position:absolute;opacity:0}
.theme-swatch{display:block;padding:14px;border:1px solid var(--line);background:var(--panel);
backdrop-filter:blur(18px) saturate(130%);
cursor:pointer}.theme-choice input:checked+.theme-swatch{border-color:var(--signal);
box-shadow:0 0 20px var(--glow)}.geo-tools{display:grid;grid-template-columns:repeat(3,minmax(220px,1fr));
gap:12px;margin:16px 0}.geo-tool{display:grid;gap:10px;padding:12px;border:1px solid var(--line);
background:rgba(var(--panel-rgb),calc(var(--glass-alpha) + .08));backdrop-filter:blur(18px) saturate(130%)}
.geo-tool h3{margin:0;color:var(--signal);font-size:12px;letter-spacing:.12em;text-transform:uppercase}
.geo-tool-row{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.geo-tool-row.single{grid-template-columns:1fr}.geo-actions{display:flex;gap:10px;flex-wrap:wrap}
.geo-actions button{flex:1;min-width:150px}.geo-map-shell{position:relative}.geo-map{width:100%;height:min(62vh,620px);
border:1px solid var(--line);background:#0a0a0d}
.map-ui{position:absolute;right:12px;top:12px;z-index:8;display:grid;gap:6px}
.map-ui button{width:38px;height:38px;padding:0;display:grid;place-items:center}
.map-night .map-tile{filter:invert(1) hue-rotate(175deg) saturate(.75) brightness(.72) contrast(1.05)}
.map-route{position:absolute;inset:0;z-index:4;pointer-events:none}
.map-route path{fill:none;stroke:var(--accent);stroke-width:4;stroke-linecap:round;stroke-linejoin:round;
filter:drop-shadow(0 0 5px var(--accent))}
.map-route-point{fill:var(--signal);stroke:#fff;stroke-width:2}
.route-controls{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:12px 0}
.quick-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(96px,1fr));gap:14px;align-items:start}
.quick-toggle{position:relative;display:grid;justify-items:center;gap:8px;padding:10px;border:1px solid transparent;
background:transparent;cursor:pointer;text-align:center}
.quick-toggle input{position:absolute;opacity:0}.quick-icon{display:grid;place-items:center;width:62px;height:62px;
border:1px solid var(--line);border-radius:50%;background:var(--panel);backdrop-filter:blur(18px) saturate(130%);
color:var(--muted);font-weight:900;letter-spacing:.02em}.quick-toggle strong{color:var(--text);font-size:13px}
.quick-toggle span{color:var(--muted);font-size:11px;line-height:1.35}.quick-toggle:has(input:checked) .quick-icon{
border-color:var(--signal);color:#03100a;background:var(--signal);box-shadow:0 0 18px var(--glow)}
.quick-toggle:has(input:checked) strong{color:var(--signal)}.recon-fields{display:grid;
grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}.recon-fields [hidden]{display:none}
.recon-result{display:grid;gap:14px}
.recon-category{padding:14px;border:1px solid var(--line);background:var(--panel);
backdrop-filter:blur(18px) saturate(130%)}.recon-category h3{margin:0 0 10px;color:var(--signal)}
.scanner-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}
.scanner-card{display:grid;gap:12px;border:1px solid var(--line);border-radius:var(--radius);
padding:16px;background:var(--field)}.scanner-card h3{margin:0;color:var(--signal)}
.scanner-card .tool-head{display:flex;align-items:center;gap:12px}.scanner-card .quick-icon{flex:0 0 auto}
.scanner-card form{display:grid;gap:10px}.scanner-card .meta-row{display:flex;gap:8px;flex-wrap:wrap}
.scanner-card .button-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.scanner-card button{width:100%}
.device-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px}
.device-card{display:grid;gap:10px;border:1px solid var(--line);border-radius:var(--radius);
padding:14px;background:var(--field)}.device-card h3{margin:0;color:var(--text);word-break:break-word}
.device-card .device-meta{display:flex;gap:8px;flex-wrap:wrap}.device-card .device-actions{display:flex;gap:8px;flex-wrap:wrap}
.device-card .device-actions a{border:1px solid var(--line);border-radius:999px;padding:7px 10px;text-decoration:none;color:var(--text)}
.profile-summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:14px}
.profile-tabs{display:grid;gap:12px}.profile-section{border:1px solid var(--line);border-radius:var(--radius);
background:var(--field);padding:12px}.profile-section h3{margin:0 0 8px;color:var(--signal)}
.action-row{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.action-row a{padding:7px 10px;
border:1px solid var(--line);border-radius:999px;background:rgba(var(--panel-rgb),.5)}
.status-badge,.risk-badge{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);
border-radius:999px;padding:4px 9px;font-size:11px;font-weight:900;text-transform:uppercase}
.risk-badge[data-risk="attention"],.status-badge[data-level="attention"]{border-color:rgba(255,138,34,.55);color:var(--orange)}
.risk-badge[data-risk="critique"],.status-badge[data-level="critique"]{border-color:rgba(255,77,89,.65);color:var(--danger)}
.metric-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.metric-card{border:1px solid var(--line);border-radius:var(--radius);padding:14px;background:var(--field)}
.metric-card strong{display:block;font-size:28px;color:var(--signal)}.metric-card span{color:var(--muted);font-size:12px}
.timeline{display:grid;gap:10px}.timeline-item{border-left:2px solid var(--line);padding:8px 0 8px 14px}
.timeline-item strong{display:block}.correlation-card{border:1px solid var(--line);border-radius:var(--radius);
padding:12px;background:var(--field);display:grid;gap:8px}
.filter-row{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}.filter-row a{border:1px solid var(--line);
border-radius:999px;padding:7px 10px;color:var(--text);text-decoration:none;background:var(--field)}
.record-card{display:grid;gap:8px;border:1px solid var(--line);border-radius:var(--radius);padding:12px;background:var(--field)}
.record-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
pre{max-width:100%;overflow:auto;
white-space:pre-wrap;word-break:break-word;padding:16px;border:1px solid var(--line);
background:var(--panel);backdrop-filter:blur(18px) saturate(130%);color:#c9fbe0}ul.clean{padding:0;list-style:none}ul.clean li{
padding:9px 0;border-bottom:1px dashed var(--line)}.hero{max-width:850px;margin:6vh auto}
.hero .card{padding:clamp(22px,5vw,46px)}
.sidebar{border-radius:var(--radius)}
nav a,.context-bar,.notice,.theme-swatch,pre,.table-wrap{border-radius:12px}
.card,.loading-panel,.map,.geo-map{border-radius:var(--radius)}
.app{border-radius:8px}.badge{border-radius:999px}
.button,button,input,select,textarea{border-radius:10px;clip-path:none}
button.danger{border-color:var(--danger);background:transparent;color:var(--danger)}
button.danger:hover{background:var(--danger);color:#fff}
.geo-map{position:relative;overflow:hidden;touch-action:none}
.map-tile{position:absolute;width:256px;height:256px;max-width:none}
.map-marker{position:absolute;left:50%;top:50%;z-index:5;width:22px;height:22px;
transform:translate(-50%,-50%);border:4px solid #fff;border-radius:50%;
background:var(--signal);box-shadow:0 0 0 8px var(--glow),0 0 22px #000}
.data-actions{display:flex;gap:8px;align-items:end;flex-wrap:wrap}
.data-actions form{display:flex;gap:8px;align-items:end;flex:1;min-width:220px}
.data-actions form.compact{flex:0 0 auto;min-width:0}
.ownership{margin-top:34px;padding-top:16px;border-top:1px solid var(--line);
color:var(--muted);font-size:11px}
@media(max-width:900px){body{--glass-alpha:.92}.shell{grid-template-columns:1fr}
.shell:not(.nav-collapsed) main{padding-left:18px;filter:blur(1px);pointer-events:none}
.topline{padding-left:58px}.sidebar{position:fixed;
left:14px;top:14px;width:min(84vw,320px);height:calc(100vh - 28px);box-shadow:20px 0 60px rgba(0,0,0,.45);
background:rgba(var(--panel-rgb),.96);backdrop-filter:blur(18px) saturate(130%)}
.shell.nav-collapsed{grid-template-columns:1fr}.shell:not(.nav-collapsed) .menu-toggle{left:min(calc(84vw + 22px),342px);
background:rgba(var(--panel-rgb),.98)}
body[data-app-mode="light"] .sidebar,body[data-app-mode="light"] .menu-toggle{background:rgba(255,255,255,.98);
color:#0f172a}
body[data-app-mode="light"] .card,body[data-app-mode="light"] input,body[data-app-mode="light"] select,
body[data-app-mode="light"] textarea,body[data-app-mode="light"] .notice,body[data-app-mode="light"] .tab-button,
body[data-app-mode="light"] .theme-swatch,body[data-app-mode="light"] .quick-icon,
body[data-app-mode="light"] .geo-tool,body[data-app-mode="light"] .recon-category{
background:rgba(255,255,255,.96);color:#0f172a}
body[data-app-mode="light"] .muted,body[data-app-mode="light"] label,
body[data-app-mode="light"] .quick-toggle span,body[data-app-mode="light"] .app span{color:#334155}
body[data-app-mode="light"] .quick-toggle strong,body[data-app-mode="light"] .app strong{color:#0f172a}
.brand{margin-bottom:14px}
nav{display:grid}.card,.card.wide{grid-column:span 6}}
@media(max-width:600px){main{padding:76px 12px 40px}.topline{padding-left:54px;gap:10px}.card,.card.wide,.card.full{
grid-column:1/-1}.topline{display:block}.table-wrap{overflow-x:auto}
.sidebar{padding:14px}.brand{margin-bottom:14px}.app-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
.app{min-height:118px;padding:8px}.app:before,.quick-icon{width:56px;height:56px;font-size:12px}
.quick-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.quick-toggle{padding:8px}
.context-bar{position:sticky;top:0;z-index:4;font-size:12px;background:rgba(var(--panel-rgb),.96)}
.geo-tools{grid-template-columns:1fr}.geo-tool-row{grid-template-columns:1fr}.geo-map{height:56vh}
h1{font-size:26px}.card{padding:16px}}
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


def _artifact_actions(category: str, item: dict[str, Any]) -> str:
    actions: list[tuple[str, str]] = []
    address = str(item.get("address") or item.get("ip") or "").strip()
    ssid = str(item.get("ssid") or "").strip()
    bluetooth = str(item.get("address") or item.get("mac") or item.get("name") or "").strip()
    if category in {"network", "ports"} and address:
        quoted = quote(address)
        actions.append(("Profiler", f"/profile?target={quoted}"))
        actions.append(("Scanner ports", f"/recon?subject={quoted}&source_ports=1"))
        actions.append(("HTTP", f"/headers?url=http://{quoted}"))
    if category == "wifi" and ssid:
        actions.append(("Sans-fil", f"/wireless?artifact={quote(ssid)}"))
    if category == "bluetooth" and bluetooth:
        actions.append(("Sans-fil", f"/wireless?artifact={quote(bluetooth)}"))
    if not actions:
        return ""
    links = "".join(
        f'<a href="{escape(href)}">{escape(label)}</a>' for label, href in actions
    )
    return f"<div class='action-row'>{links}</div>"


def _recon_result(value: dict[str, Any]) -> str:
    categories = value.get("categories")
    if not isinstance(categories, dict):
        return _value(value)
    view = str(value.get("view") or "category")
    blocks = [
        f"<p class='muted'>Vue : {escape(view)} · Durée : "
        f"{escape(str(value.get('duration_seconds', '-')))} s</p>"
    ]
    for key, section in categories.items():
        if not isinstance(section, dict):
            continue
        title = str(section.get("title") or key)
        items = section.get("items", [])
        description = str(section.get("description") or "")
        limitations = section.get("limitations", [])
        body = _value(items)
        if view == "list" and isinstance(items, list):
            body = "<ul class='clean'>" + "".join(
                f"<li>{_value(item)}{_artifact_actions(key, item) if isinstance(item, dict) else ''}</li>"
                for item in items
            ) + "</ul>"
        elif view == "table" and isinstance(items, list) and all(isinstance(item, dict) for item in items):
            body += "".join(_artifact_actions(key, item) for item in items[:8])
        blocks.append(
            f"<section class='recon-category'><h3>{escape(title)}</h3>"
            f"<p class='muted'>{escape(str(section.get('engine', '')))}</p>"
            f"{f'<p>{escape(description)}</p>' if description else ''}"
            f"{_value(limitations) if limitations else ''}{body}</section>"
        )
    suggestions = value.get("suggestions", [])
    records = value.get("records")
    if isinstance(records, dict):
        blocks.append(
            "<section class='recon-category'><h3>DonnÃ©es crÃ©Ã©es</h3>"
            f"{_value(records)}</section>"
        )
    if suggestions:
        blocks.append("<section class='recon-category'><h3>Suites possibles</h3>" + _value(suggestions) + "</section>")
    return "<div class='recon-result'>" + "".join(blocks) + "</div>"


def _records_metrics() -> str:
    summary = records_summary()
    return (
        "<div class='metric-row'>"
        f"<div class='metric-card'><strong>{summary['artifacts']}</strong><span>artefacts JSON</span></div>"
        f"<div class='metric-card'><strong>{summary['events']}</strong><span>evenements timeline</span></div>"
        f"<div class='metric-card'><strong>{summary['correlations']}</strong><span>correlations</span></div>"
        "</div>"
    )


def _timeline_preview(limit: int = 5) -> str:
    events = []
    for path in list_records("event")[:limit]:
        payload = load_record(path)
        level = escape(str(payload.get("level", "info")))
        events.append(
            "<div class='timeline-item'>"
            f"<span class='status-badge' data-level='{level}'>{level}</span>"
            f"<strong>{escape(str(payload.get('description', 'Evenement')))}</strong>"
            f"<span class='muted'>{escape(str(payload.get('created_at', '')).replace('T', ' '))}"
            f" · {escape(str(payload.get('source', '')))}</span></div>"
        )
    if not events:
        return "<p class='muted'>Aucun evenement enregistre pour le moment.</p>"
    return "<div class='timeline'>" + "".join(events) + "</div>"


def _record_filters() -> str:
    return """<div class="filter-row">
<a href="/reports">Tout</a><a href="/reports#timeline">Timeline</a>
<a href="/reports#correlations">Corrélations</a><a href="/devices">Appareils</a>
<a href="/scanner">Scanner</a></div>"""


def _artifact_board(limit: int = 40) -> str:
    cards = []
    for path in list_records("artifact")[:limit]:
        payload = load_record(path)
        risk = escape(str(payload.get("risk", "info")))
        kind = escape(str(payload.get("kind", "artifact")))
        confidence = escape(str(payload.get("confidence", "faible")))
        cards.append(
            "<article class='record-card'>"
            f"<span class='risk-badge' data-risk='{risk}'>{risk}</span>"
            f"<strong>{escape(str(payload.get('title', 'Artefact')))}</strong>"
            f"<span>{escape(str(payload.get('summary', '')))}</span>"
            f"<span class='muted'>{kind} · confiance {confidence} · {escape(str(payload.get('created_at', '')).replace('T', ' '))}</span>"
            "<div class='action-row'><a href='/reports#timeline'>Timeline</a>"
            "<a href='/reports#correlations'>Corréler</a></div></article>"
        )
    if not cards:
        return "<p class='muted'>Aucun artefact disponible.</p>"
    return "<div class='record-grid'>" + "".join(cards) + "</div>"


def _timeline_board(limit: int = 50) -> str:
    rows = []
    for path in list_records("event")[:limit]:
        payload = load_record(path)
        level = escape(str(payload.get("level", "info")))
        event_type = escape(str(payload.get("event_type", "event")))
        source = escape(str(payload.get("source", "")))
        link = escape(str(payload.get("link") or "/reports"))
        rows.append(
            "<div class='timeline-item'>"
            f"<span class='status-badge' data-level='{level}'>{level}</span>"
            f"<strong>{escape(str(payload.get('description', 'Evenement')))}</strong>"
            f"<span class='muted'>{escape(str(payload.get('created_at', '')).replace('T', ' '))} · {source} · {event_type}</span>"
            f"<div class='action-row'><a href='{link}'>Ouvrir</a><a href='/reports#correlations'>Corréler</a></div></div>"
        )
    if not rows:
        return "<p class='muted'>Aucun événement enregistre pour le moment.</p>"
    return _record_filters() + "<div class='timeline' id='timeline'>" + "".join(rows) + "</div>"


def _correlation_preview(limit: int = 5) -> str:
    cards = []
    for path in list_records("correlation")[:limit]:
        payload = load_record(path)
        severity = escape(str(payload.get("severity", "info")))
        recommendations = payload.get("recommendations", [])
        recommendation = recommendations[0] if isinstance(recommendations, list) and recommendations else ""
        recommendation_html = (
            f"<span class='muted'>{escape(str(recommendation))}</span>"
            if recommendation else ""
        )
        cards.append(
            "<div class='correlation-card'>"
            f"<span class='risk-badge' data-risk='{severity}'>{severity}</span>"
            f"<strong>{escape(str(payload.get('title', 'Correlation')))}</strong>"
            f"<span>{escape(str(payload.get('hypothesis', '')))}</span>"
            f"{recommendation_html}"
            "</div>"
        )
    if not cards:
        return "<p class='muted'>Aucune correlation generee pour le moment.</p>"
    return "<div class='timeline'>" + "".join(cards) + "</div>"


def _correlation_board(limit: int = 50) -> str:
    cards = []
    for path in list_records("correlation")[:limit]:
        payload = load_record(path)
        severity = escape(str(payload.get("severity", "info")))
        confidence = escape(str(payload.get("confidence", "faible")))
        evidence = payload.get("evidence", [])
        recommendations = payload.get("recommendations", [])
        evidence_html = _value(evidence[:4] if isinstance(evidence, list) else evidence)
        recommendation_html = _value(recommendations[:3] if isinstance(recommendations, list) else recommendations)
        cards.append(
            "<article class='correlation-card'>"
            f"<span class='risk-badge' data-risk='{severity}'>{severity}</span>"
            f"<strong>{escape(str(payload.get('title', 'Correlation')))}</strong>"
            f"<span>{escape(str(payload.get('hypothesis', '')))}</span>"
            f"<span class='muted'>Confiance {confidence} · {escape(str(payload.get('created_at', '')).replace('T', ' '))}</span>"
            f"<details><summary>Preuves</summary>{evidence_html}</details>"
            f"<details><summary>Recommandations</summary>{recommendation_html}</details>"
            "<div class='action-row'><a href='/reports'>Ajouter au rapport</a><a href='/devices'>Voir appareils</a></div>"
            "</article>"
        )
    if not cards:
        return "<p class='muted'>Aucune corrélation générée pour le moment.</p>"
    return _record_filters() + "<div class='record-grid' id='correlations'>" + "".join(cards) + "</div>"


def _device_inventory() -> list[dict[str, Any]]:
    devices: dict[str, dict[str, Any]] = {}
    exposure = exposure_inventory()
    for address, asset in exposure.get("assets", {}).items():
        devices[address] = {
            "address": address,
            "title": str(asset.get("label") or address),
            "kind": "Appareil réseau",
            "confidence": "moyenne",
            "risk": "attention" if asset.get("findings") else "info",
            "services": asset.get("services", []),
            "last_seen": str(asset.get("last_seen", "")),
            "source": "historique ports",
            "findings": asset.get("findings", []),
        }
    for path in list_records("artifact"):
        payload = load_record(path)
        if payload.get("kind") not in {"device", "device_profile"}:
            continue
        data = payload.get("data", {}) if isinstance(payload.get("data"), dict) else {}
        address = str(payload.get("value") or data.get("address") or data.get("ip") or payload.get("title") or "")
        if not address:
            continue
        current = devices.setdefault(address, {"address": address, "services": [], "findings": []})
        services = data.get("services", current.get("services", []))
        current.update({
            "title": str(payload.get("title") or address),
            "kind": str(data.get("device_type") or "Appareil observé"),
            "confidence": str(payload.get("confidence") or current.get("confidence") or "faible"),
            "risk": str(payload.get("risk") or current.get("risk") or "info"),
            "services": services if isinstance(services, list) else current.get("services", []),
            "last_seen": str(payload.get("created_at") or current.get("last_seen") or ""),
            "source": str(payload.get("source") or current.get("source") or "artifact"),
        })
    return sorted(devices.values(), key=lambda item: str(item.get("last_seen", "")), reverse=True)


def _device_cards() -> str:
    cards = []
    for device in _device_inventory():
        address = str(device.get("address") or "")
        services = device.get("services", [])
        service_count = len(services) if isinstance(services, list) else 0
        risk = escape(str(device.get("risk") or "info"))
        confidence = escape(str(device.get("confidence") or "faible"))
        quoted = quote(address)
        cards.append(
            "<article class='device-card'>"
            f"<div><h3>{escape(str(device.get('title') or address))}</h3>"
            f"<span class='muted'>{escape(address)}</span></div>"
            f"<div class='device-meta'><span class='risk-badge' data-risk='{risk}'>{risk}</span>"
            f"<span class='status-badge'>{confidence}</span><span class='badge'>{service_count} services</span></div>"
            f"<p class='muted'>Dernière activité : {escape(str(device.get('last_seen') or '-'))}</p>"
            f"<p>{escape(str(device.get('kind') or 'Appareil'))}</p>"
            f"<div class='device-actions'><a href='/profile?target={quoted}'>Voir fiche</a>"
            f"<a href='/recon?subject={quoted}&target={quoted}&source_ports=1'>Scanner ports</a>"
            f"<a href='/reports'>Corréler</a></div></article>"
        )
    if not cards:
        return "<p class='muted'>Aucun appareil conservé pour le moment. Lance un scan réseau ou ports avec conservation.</p>"
    return "<div class='device-grid'>" + "".join(cards) + "</div>"


def _profile_result(value: dict[str, Any]) -> str:
    summary = {
        "Adresse": value.get("address", "-"),
        "Nom": value.get("hostname", "-"),
        "Type probable": value.get("device_type", "-"),
        "Confiance": value.get("confidence", "faible"),
        "Fabricant": value.get("manufacturer", "-") or "-",
        "MAC": value.get("mac_address", "-") or "-",
    }
    actions = ""
    address = str(value.get("address") or value.get("target") or "")
    if address:
        quoted = quote(address)
        actions = (
            "<div class='action-row'>"
            f"<a href='/recon?subject={quoted}&target={quoted}&source_ports=1'>Scanner ports</a>"
            f"<a href='/headers?url=http://{quoted}'>HTTP passif</a>"
            "<a href='/reports'>Voir timeline/corrélations</a></div>"
        )
    sections = [
        ("Résumé", _value(summary)),
        ("Services", _value(value.get("services", []))),
        ("Indices utilisés", _value(value.get("evidence", []))),
        ("Noms observés", _value(value.get("name_observations", []))),
        ("Corrélations", _value(value.get("correlations", []))),
        ("Limites", _value(value.get("limitations", []))),
    ]
    blocks = "".join(
        f"<section class='profile-section'><h3>{escape(title)}</h3>{body}</section>"
        for title, body in sections
    )
    return f"<div class='profile-summary'>{_records_metrics()}</div><div class='profile-tabs'>{blocks}</div>{actions}"


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
        self.recon_form: dict[str, str | bool] = {}
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
    nav = """<nav><a href="/">Accueil</a><a href="/kill-chain">Kill Chain</a>
<a href="/scanner">Scanner</a><a href="/devices">Appareils</a>
<a href="/monitoring">Monitoring</a><a href="/map">Carte</a>
<a href="/tools">Outils</a><a href="/missions">Missions</a>
<a href="/reports">Rapports</a><a href="/settings">Paramètres</a></nav>"""
    context = local_context()
    body_class = "" if settings.glass_effect else "no-glass"
    glass_alpha = f"{settings.glass_opacity:.2f}"
    night = datetime.now().hour >= 19 or datetime.now().hour < 7
    app_mode = ("dark" if night else "light") if settings.app_color_mode == "auto" else settings.app_color_mode
    map_mode = ("night" if night else "day") if settings.map_color_mode == "auto" else settings.map_color_mode
    return f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title><style>{CSS}</style></head>
<body class="{body_class}" data-theme="{escape(settings.theme)}" data-app-mode="{app_mode}"
data-map-mode="{map_mode}" style="--glass-alpha:{glass_alpha}">
<div class="shell nav-collapsed" id="app-shell">
<aside class="sidebar"><div class="brand"><div class="sc-wordmark"><span>SC</span><span class="sc-mark"></span></div>
<strong>recon SC</strong><small>Observe. Profile. Correlate.</small><div class="status"><span class="pulse"></span>
SESSION LOCALE ACTIVE</div></div>{nav}</aside><main><div class="topline"><div>
<button class="menu-toggle" id="menu-toggle" type="button" aria-label="Afficher ou masquer le menu">☰</button>
<span class="eyebrow">recon SC // interface locale autorisée</span><h1>{escape(title)}</h1></div>
<span class="muted">LOCAL // AUTHORIZED</span></div>
<div class="context-bar"><span id="live-clock">{escape(context['time'])}</span>
<span>{escape(context['timezone'])}</span><span>{escape(context['platform'])}</span></div>
{body}<footer class="ownership">recon SC · Cyber Learning Toolbox © 2026 Maréchaux Willem ·
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
menuToggle.addEventListener("click",()=>{{
shell.classList.toggle("nav-collapsed");
}});
const params=new URLSearchParams(window.location.search);
if([...params.keys()].some(key=>key.startsWith("source_"))){{
document.querySelectorAll('[name^="source_"]').forEach(item=>item.checked=false);
}}
params.forEach((value,key)=>{{
const field=document.querySelector(`[name="${{CSS.escape(key)}}"]`);
if(field?.type==="checkbox")field.checked=["1","true","on","yes"].includes(String(value).toLowerCase());
else if(field&&"value" in field)field.value=value;
}});
function syncReconFields(){{
const hasDiscover=document.querySelector('[name="source_discover"]')?.checked;
const hasPorts=document.querySelector('[name="source_ports"]')?.checked;
const hasHttp=document.querySelector('[name="source_http"]')?.checked;
const rules={{network:hasDiscover,target:hasPorts||hasHttp,ports:hasPorts}};
document.querySelectorAll("[data-recon-field]").forEach(field=>{{
field.hidden=!rules[field.dataset.reconField];
}});
const subject=document.querySelector('[name="subject"]');
const target=document.querySelector('[name="target"]');
const network=document.querySelector('[name="network"]');
if(subject){{
if((hasPorts||hasHttp)&&target?.value)subject.value=target.value;
else if(hasDiscover&&network?.value)subject.value=network.value;
}}
}}
document.querySelectorAll('[name^="source_"]').forEach(item=>item.addEventListener("change",syncReconFields));
document.querySelectorAll('[name="network"],[name="target"]').forEach(item=>item.addEventListener("input",syncReconFields));
syncReconFields();
const appIcons={{
operations:"OPS",recon:"IP",profiler:"ID",labs:"LAB","sans-fil":"WIFI",
inventaire:"INV",cartographie:"MAP",archives:"ARC",tools:"TLS",context:"CTX",
"signal fantôme":"LAB","mission réseau":"IP","profil autorisé":"ID",
"kill chain":"KC",scanner:"SCAN",appareils:"DEV",monitoring:"MON",
"carte":"MAP","missions":"MIS","rapports":"REP","reconnaissance":"REC",
"scan":"SCAN","énumération":"ENUM","analyse":"ANA","hypothèses":"HYP",
"corrélation":"COR","recommandations":"REC","rapport":"REP"
}};
document.querySelectorAll(".app").forEach(item=>{{
const label=item.querySelector("strong")?.textContent?.trim().toLowerCase()||"";
item.dataset.icon=appIcons[label]||label.slice(0,3).toUpperCase()||"GO";
}});
document.querySelectorAll(".sidebar a").forEach(link=>link.addEventListener("click",()=>{{
if(window.innerWidth<900)shell.classList.add("nav-collapsed");
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
document.querySelector("[name=glass_opacity]")?.addEventListener("input",event=>{{
document.body.style.setProperty("--glass-alpha",event.target.value);
document.getElementById("glass-opacity-value").textContent=Number(event.target.value).toFixed(2);
}});
function effectiveAppMode(value){{
const hour=new Date().getHours();return value==="auto"?(hour>=19||hour<7?"dark":"light"):value;
}}
function effectiveMapMode(value){{
const hour=new Date().getHours();return value==="auto"?(hour>=19||hour<7?"night":"day"):value;
}}
function previewModes(){{
const appValue=document.querySelector("[name=app_color_mode]:checked")?.value||"auto";
const mapValue=document.querySelector("[name=map_color_mode]:checked")?.value||"auto";
const appTrack=document.querySelector('[data-mode-track="app"]');
const mapTrack=document.querySelector('[data-mode-track="map"]');
if(appTrack)appTrack.dataset.value=appValue;
if(mapTrack)mapTrack.dataset.value=mapValue;
document.body.dataset.appMode=effectiveAppMode(appValue);
document.body.dataset.mapMode=effectiveMapMode(mapValue);
renderGeoMap();
}}
["app_color_mode","map_color_mode"].forEach(name=>{{
document.querySelectorAll(`[name=${{name}}]`).forEach(item=>item.addEventListener("change",previewModes));
}});
const mapProviders={{
standard:{{url:"https://tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png",
label:"OpenStreetMap Standard",maxZoom:19}},
topographic:{{url:"https://a.tile.opentopomap.org/{{z}}/{{x}}/{{y}}.png",
label:"OpenTopoMap",maxZoom:17}}
}};
let mapPinchDistance=0;
let mapDrag=null;
const geoState={{lat:null,lon:null,markerLat:null,markerLon:null,zoom:16,route:[]}};
function redrawGeoMap(){{
const lat=document.getElementById("map-latitude")?.value;
const lon=document.getElementById("map-longitude")?.value;
if(lat&&lon)showGeoMap(lat,lon);
}}
function adjustGeoZoom(delta){{
const zoom=document.getElementById("map-zoom");
if(!zoom)return;
zoom.value=String(Math.max(2,Math.min(19,(Number(zoom.value)||16)+delta)));
geoState.zoom=Number(zoom.value)||16;
renderGeoMap();
}}
function recenterGeoMap(){{
const status=document.getElementById("geo-map-status");
if(geoState.markerLat===null||geoState.markerLon===null){{
status.textContent="Aucun marqueur à recentrer. Saisissez une position, recherchez une adresse ou utilisez votre position.";
return;
}}
geoState.lat=geoState.markerLat;
geoState.lon=geoState.markerLon;
renderGeoMap();
}}
function latLonToTile(lat,lon,zoom){{
const n=2**zoom;
lat=Math.max(-85.05112878,Math.min(85.05112878,lat));
const latRad=lat*Math.PI/180;
return {{x:(lon+180)/360*n,y:(1-Math.asinh(Math.tan(latRad))/Math.PI)/2*n}};
}}
function tileToLatLon(x,y,zoom){{
const n=2**zoom;
return {{lat:Math.atan(Math.sinh(Math.PI*(1-2*y/n)))*180/Math.PI,lon:x/n*360-180}};
}}
function screenPoint(lat,lon,centerX,centerY,zoom,width,height){{
const tile=latLonToTile(lat,lon,zoom);
return {{x:width/2+(tile.x-centerX)*256,y:height/2+(tile.y-centerY)*256}};
}}
function drawRoute(map,centerX,centerY,zoom,width,height){{
if(!geoState.route.length)return;
const svg=document.createElementNS("http://www.w3.org/2000/svg","svg");
svg.setAttribute("class","map-route");svg.setAttribute("viewBox",`0 0 ${{width}} ${{height}}`);
const points=geoState.route.map(item=>screenPoint(item.lat,item.lon,centerX,centerY,zoom,width,height));
const path=document.createElementNS("http://www.w3.org/2000/svg","path");
path.setAttribute("d",points.map((p,i)=>(i?"L":"M")+p.x.toFixed(1)+" "+p.y.toFixed(1)).join(" "));
svg.appendChild(path);
[points[0],points[points.length-1]].filter(Boolean).forEach(point=>{{
const circle=document.createElementNS("http://www.w3.org/2000/svg","circle");
circle.setAttribute("class","map-route-point");circle.setAttribute("cx",point.x);circle.setAttribute("cy",point.y);
circle.setAttribute("r","5");svg.appendChild(circle);
}});
map.appendChild(svg);
}}
async function geocodeAddress(value){{
const query=String(value||"").trim();
if(!query)throw new Error("Adresse vide.");
const url="https://nominatim.openstreetmap.org/search?format=json&limit=1&q="+encodeURIComponent(query);
const response=await fetch(url,{{headers:{{"Accept":"application/json"}}}});
if(!response.ok)throw new Error("Recherche d'adresse indisponible pour le moment.");
const items=await response.json();
if(!items.length)throw new Error("Adresse introuvable.");
return {{lat:Number(items[0].lat),lon:Number(items[0].lon),label:items[0].display_name}};
}}
async function searchMapAddress(){{
const status=document.getElementById("geo-map-status");
try{{
status.textContent="Recherche de l'adresse...";
const result=await geocodeAddress(document.getElementById("map-search").value);
document.getElementById("map-latitude").value=result.lat.toFixed(5);
document.getElementById("map-longitude").value=result.lon.toFixed(5);
showGeoMap(result.lat,result.lon);
status.textContent="Adresse trouvée : "+result.label;
}}catch(error){{status.textContent=error.message;}}
}}
async function routeFromMap(){{
const status=document.getElementById("geo-map-status");
try{{
status.textContent="Calcul de l'itinéraire...";
let start;
if(document.getElementById("route-start-mode").value==="current"){{
start={{lat:geoState.markerLat??geoState.lat,lon:geoState.markerLon??geoState.lon}};
if(start.lat===null||start.lon===null)throw new Error("Indiquez ou localisez d'abord un point de départ.");
}}else start=await geocodeAddress(document.getElementById("route-start").value);
const end=await geocodeAddress(document.getElementById("route-end").value);
const profile=document.getElementById("route-profile").value;
const url=`https://router.project-osrm.org/route/v1/${{profile}}/${{start.lon}},${{start.lat}};${{end.lon}},${{end.lat}}?overview=full&geometries=geojson`;
const response=await fetch(url);
if(!response.ok)throw new Error("Service d'itineraire indisponible pour ce mode.");
const payload=await response.json();
if(payload.code!=="Ok"||!payload.routes?.length)throw new Error("Itineraire indisponible pour ces points.");
geoState.route=payload.routes[0].geometry.coordinates.map(item=>({{lon:item[0],lat:item[1]}}));
geoState.lat=(start.lat+end.lat)/2;geoState.lon=(start.lon+end.lon)/2;geoState.markerLat=end.lat;geoState.markerLon=end.lon;
renderGeoMap();
status.textContent="Itinéraire : "+(payload.routes[0].distance/1000).toFixed(1)+" km.";
}}catch(error){{status.textContent=error.message;}}
}}
function showGeoMap(latitude,longitude){{
let lat=Number(latitude);const lon=Number(longitude);
if(!Number.isFinite(lat)||!Number.isFinite(lon)||lat<-90||lat>90||lon<-180||lon>180)return;
geoState.lat=Math.max(-85.05112878,Math.min(85.05112878,lat));
geoState.lon=lon;
geoState.markerLat=geoState.lat;
geoState.markerLon=lon;
geoState.zoom=Number(document.getElementById("map-zoom").value)||geoState.zoom||16;
renderGeoMap();
}}
function renderGeoMap(){{
if(geoState.lat===null||geoState.lon===null)return;
let lat=Number(geoState.lat);const lon=Number(geoState.lon);
lat=Math.max(-85.05112878,Math.min(85.05112878,lat));
const map=document.getElementById("geo-map-frame");
const provider=mapProviders[document.getElementById("map-layer").value]||mapProviders.standard;
const requestedZoom=Number(geoState.zoom)||15;
const zoom=Math.min(requestedZoom,provider.maxZoom);
geoState.zoom=zoom;document.getElementById("map-zoom").value=String(zoom);
const n=2**zoom;
const center=latLonToTile(lat,lon,zoom);
const x=center.x,y=center.y;
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
if(geoState.markerLat!==null&&geoState.markerLon!==null){{
const markerTile=latLonToTile(geoState.markerLat,geoState.markerLon,zoom);
marker.style.left=(width/2+(markerTile.x-x)*256)+"px";
marker.style.top=(height/2+(markerTile.y-y)*256)+"px";
marker.title=geoState.markerLat.toFixed(5)+", "+geoState.markerLon.toFixed(5);
map.appendChild(marker);
}}
map.classList.toggle("map-night",document.body.dataset.mapMode==="night");
drawRoute(map,x,y,zoom,width,height);
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
window.addEventListener("DOMContentLoaded",()=>{{
const map=document.getElementById("geo-map-frame");
if(!map)return;
map.addEventListener("wheel",event=>{{
event.preventDefault();
adjustGeoZoom(event.deltaY<0?1:-1);
}},{{passive:false}});
map.addEventListener("pointerdown",event=>{{
if(geoState.lat===null||event.pointerType==="touch"&&event.isPrimary===false)return;
map.setPointerCapture(event.pointerId);
mapDrag={{id:event.pointerId,startX:event.clientX,startY:event.clientY,
center:latLonToTile(geoState.lat,geoState.lon,geoState.zoom),zoom:geoState.zoom}};
}});
map.addEventListener("pointermove",event=>{{
if(!mapDrag||mapDrag.id!==event.pointerId)return;
const moved=tileToLatLon(
mapDrag.center.x-(event.clientX-mapDrag.startX)/256,
mapDrag.center.y-(event.clientY-mapDrag.startY)/256,
mapDrag.zoom
);
geoState.lat=Math.max(-85.05112878,Math.min(85.05112878,moved.lat));
geoState.lon=((moved.lon+540)%360)-180;
renderGeoMap();
}});
map.addEventListener("pointerup",event=>{{if(mapDrag?.id===event.pointerId)mapDrag=null;}});
map.addEventListener("pointercancel",()=>mapDrag=null);
map.addEventListener("touchmove",event=>{{
if(event.touches.length!==2)return;
const a=event.touches[0],b=event.touches[1];
const distance=Math.hypot(a.clientX-b.clientX,a.clientY-b.clientY);
if(mapPinchDistance&&Math.abs(distance-mapPinchDistance)>36){{
adjustGeoZoom(distance>mapPinchDistance?1:-1);
mapPinchDistance=distance;
}}else if(!mapPinchDistance)mapPinchDistance=distance;
event.preventDefault();
}},{{passive:false}});
map.addEventListener("touchend",()=>mapPinchDistance=0);
document.getElementById("map-layer")?.addEventListener("change",redrawGeoMap);
document.getElementById("map-zoom")?.addEventListener("change",redrawGeoMap);
}});
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
const route=(new URL(form.action)).pathname.split("/").filter(Boolean).pop()||"default";
if(form.dataset.confirm&&!window.confirm(form.dataset.confirm)){{event.preventDefault();return;}}
if(route==="settings")return;
event.preventDefault();
form.dataset.loading="1";
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
            "/kill-chain": self._kill_chain,
            "/scanner": self._recon,
            "/devices": self._profile,
            "/monitoring": self._monitoring,
            "/missions": self._missions,
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
        route_path = urlparse(self.path).path
        local_routes = {
            "/profile",
            "/recon",
            "/headers",
            "/lab",
            "/wireless",
            "/context",
            "/tools",
            "/data",
            "/settings",
        }
        if _field(data, "token") != self.state.token and route_path not in local_routes:
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
        handler = handlers.get(route_path)
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
        if route == "/recon":
            body = _recon_result(self.state.result)
        elif route == "/profile":
            body = _profile_result(self.state.result)
        else:
            body = _value(self.state.result)
        return f"<section class='card full'><h2>{escape(self.state.result_title)}</h2>{body}</section>"

    def _home(self) -> None:
        if not self.state.accepted:
            body = f"""<section class="card full"><span class="eyebrow">Accès contrôlé</span>
<h1>recon SC</h1><p>Observe. Profile. Correlate.</p><p>Cette console est réservée à l'apprentissage,
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
        record_metrics = _records_metrics()
        timeline = _timeline_preview(4)
        body = f"""<div class="grid"><section class="card wide">
<span class="eyebrow">Observe. Profile. Correlate.</span><h2>recon SC</h2>
<p>Console locale défensive pour observer un périmètre autorisé, profiler les
appareils, corréler les preuves et préparer une restitution claire.</p>
<a class="button" href="/scanner">OUVRIR LE SCANNER</a>
</section><section class="card"><span class="eyebrow">Appareils observés</span>
<div class="metric">{exposure['asset_count']:02d}</div><p>actifs indexés</p>
<span class="badge">{exposure['service_count']} services</span></section>
<section class="card full"><div class="group-label">Kill chain défensive</div>
<div class="app-grid">
<a class="app" href="/scanner"><strong>Reconnaissance</strong><span>Réseau, Wi-Fi, Bluetooth, HTTP</span></a>
<a class="app" href="/scanner"><strong>Scan</strong><span>Hôtes actifs et ports TCP</span></a>
<a class="app" href="/devices"><strong>Énumération</strong><span>Fiche appareil et services</span></a>
<a class="app" href="/tools"><strong>Analyse</strong><span>DNS, TLS, journaux, fichiers</span></a>
<a class="app" href="/kill-chain"><strong>Hypothèses</strong><span>Axes d'action défensifs</span></a>
<a class="app" href="/reports"><strong>Rapport</strong><span>Preuves, constats et recommandations</span></a>
</div></section>
<section class="card full"><div class="group-label">Modules</div>
<div class="app-grid">
<a class="app" href="/kill-chain"><strong>Kill Chain</strong><span>Parcours défensif guidé</span></a>
<a class="app" href="/scanner"><strong>Scanner</strong><span>Recon locale autorisée</span></a>
<a class="app" href="/devices"><strong>Appareils</strong><span>Profil et confiance</span></a>
<a class="app" href="/monitoring"><strong>Monitoring</strong><span>Santé locale et exposition</span></a>
<a class="app" href="/map"><strong>Carte</strong><span>Carte et topologie réseau</span></a>
<a class="app" href="/tools"><strong>Outils</strong><span>Système, hash, DNS, TLS</span></a>
<a class="app" href="/missions"><strong>Missions</strong><span>Scénarios pédagogiques</span></a>
<a class="app" href="/reports"><strong>Rapports</strong>
<span>{history_count} historiques / {len(list_reports())} rapports</span></a>
</div></section><section class="card full"><h2>DonnÃ©es rÃ©utilisables</h2>
{record_metrics}</section><section class="card full"><h2>Timeline rÃ©cente</h2>
{timeline}</section><section class="card full"><h2>Configuration active</h2>
{_value(dict(settings_summary(settings)))}</section></div>"""
        self._send(render_layout("Accueil", body))

    def _accept(self, data: dict[str, list[str]]) -> None:
        if _checked(data, "accepted"):
            self.state.accepted = True
        self._redirect("/")

    def _kill_chain(self) -> None:
        steps = [
            ("Reconnaissance", "Observer le réseau, le Wi-Fi, le Bluetooth et HTTP.", "/scanner"),
            ("Scan", "Identifier les hôtes actifs et les ports exposés.", "/scanner"),
            ("Énumération", "Transformer une cible en fiche appareil.", "/devices"),
            ("Analyse", "Lire DNS, TLS, journaux, fichiers et configuration.", "/tools"),
            ("Hypothèses", "Formuler des axes défensifs sans exploitation active.", "/reports"),
            ("Corrélation", "Relier actifs, preuves, historique et exposition.", "/reports"),
            ("Recommandations", "Prioriser les corrections et limites de confiance.", "/reports"),
            ("Rapport", "Restituer les constats et le périmètre autorisé.", "/reports"),
        ]
        cards = "".join(
            f'<a class="app" href="{href}"><strong>{escape(name)}</strong><span>{escape(text)}</span></a>'
            for name, text, href in steps
        )
        body = f"""<div class="grid"><section class="card full">
<span class="eyebrow">Defensive workflow</span><h2>Kill chain recon SC</h2>
<p>Chaque étape doit produire une donnée réutilisable : fiche, timeline,
corrélation ou rapport. Les phases offensives restent théoriques ou limitées
aux labs locaux autorisés.</p><div class="app-grid">{cards}</div></section>
<section class="card full"><h2>Règle de périmètre</h2><p>Un SSID visible ne donne
pas accès aux appareils du réseau. La découverte d'hôtes nécessite d'être
connecté au réseau ou d'avoir une route explicitement autorisée.</p></section></div>"""
        self._send(render_layout("Kill Chain", body))

    def _monitoring(self) -> None:
        exposure = exposure_inventory()
        context = local_context()
        body = f"""<div class="grid"><section class="card wide">
<span class="eyebrow">Monitoring local</span><h2>État de la session</h2>
{_value({"plateforme": context["platform"], "heure": context["time"], "zone": context["timezone"]})}
</section><section class="card"><span class="eyebrow">Exposition</span>
<div class="metric">{exposure['asset_count']:02d}</div><p>actifs observés</p>
<span class="badge">{exposure['service_count']} services</span></section>
<section class="card full"><h2>Suites possibles</h2><div class="app-grid">
<a class="app" href="/tools"><strong>Audit local</strong><span>Santé système et configuration</span></a>
<a class="app" href="/exposure"><strong>Inventaire</strong><span>Actifs et services collectés</span></a>
<a class="app" href="/reports"><strong>Rapports</strong><span>Historique et restitution</span></a>
</div></section></div>"""
        self._send(render_layout("Monitoring", body))

    def _missions(self) -> None:
        missions = list_missions()
        mission_count = len(missions)
        body = f"""<div class="grid"><section class="card wide">
<span class="eyebrow">Labs autorisés</span><h2>Missions</h2>
<p>Scénarios courts pour apprendre à collecter, lire et corréler des preuves.
Les missions offensives restent simulées, offline ou locales.</p>
<a class="button" href="/lab">PRÉPARER UN LAB LOCAL</a></section>
<section class="card"><span class="eyebrow">Progression</span>
<div class="metric">{mission_count:02d}</div><p>missions enregistrées</p></section>
<section class="card full"><h2>Parcours proposés</h2><div class="app-grid">
<a class="app" href="/scanner"><strong>Mission réseau</strong><span>Découvrir puis profiler un actif autorisé</span></a>
<a class="app" href="/wireless"><strong>Mission sans-fil</strong><span>Observer Wi-Fi/Bluetooth sans connexion</span></a>
<a class="app" href="/lab"><strong>Mission lab</strong><span>Journaux, payload factice et script local</span></a>
</div></section></div>"""
        self._send(render_layout("Missions", body))

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
        default_network = local_ipv4_network()
        form_state = {
            "source_discover": False,
            "source_ports": False,
            "source_wifi": False,
            "source_bluetooth": False,
            "source_http": False,
            "authorized": False,
            "keep": True,
            "subject": "",
            "network": default_network,
            "target": "",
            "ports": settings.default_ports,
            "view": "category",
            **self.state.recon_form,
        }

        def checked(name: str) -> str:
            return " checked" if form_state.get(name) else ""

        def selected(value: str) -> str:
            return " selected" if form_state.get("view") == value else ""

        if not any(form_state.get(name) for name in (
            "source_discover",
            "source_ports",
            "source_wifi",
            "source_bluetooth",
            "source_http",
        )):
            form_state["source_wifi"] = True
        subject_value = escape(str(form_state.get("subject", "")))
        network_value = escape(str(form_state.get("network") or default_network))
        target_value = escape(str(form_state.get("target") or form_state.get("subject") or ""))
        ports_value = escape(str(form_state.get("ports") or settings.default_ports))
        view_select = f"""<label>Vue des résultats<select name="view">
<option value="category"{selected("category")}>Catégories séparées</option>
<option value="table"{selected("table")}>Tableaux</option>
<option value="list"{selected("list")}>Liste avec actions</option>
</select></label>"""
        consent = (
            f'<label class="check"><input type="checkbox" name="authorized" required{checked("authorized")}>'
            "Je confirme disposer de l'autorisation sur ce périmètre.</label>"
        )
        keep = (
            f'<label class="check"><input type="checkbox" name="keep"{checked("keep")}>'
            "Conserver et produire des données réutilisables.</label>"
        )
        body = f"""<div class="grid"><section class="card full"><span class="eyebrow">Scanner</span>
<h2>Recon autorisée</h2><p class="muted">Chaque carte lance une collecte courte,
lisible et réutilisable. Wi-Fi et Bluetooth utilisent uniquement les API locales
du système : aucune connexion, capture, désauthentification ou appairage.</p>
<div class="scanner-grid">
<article class="scanner-card"><div class="tool-head"><span class="quick-icon">IP</span>
<div><h3>Scan réseau local</h3><p class="muted">Hôtes actifs sur un réseau privé autorisé.</p></div></div>
<div class="meta-row"><span class="risk-badge">autorisé</span><span class="status-badge">local</span></div>
<form method="post" action="/recon">{self._token()}<input type="hidden" name="source_discover" value="1">
<input type="hidden" name="subject" value="{subject_value}">
<label>Réseau local autorisé<input name="network" value="{network_value}" placeholder="192.168.1.0/24"></label>
{view_select}{consent}{keep}<button type="submit">LANCER</button></form></article>

<article class="scanner-card"><div class="tool-head"><span class="quick-icon">WIFI</span>
<div><h3>Wi-Fi Analyzer</h3><p class="muted">Réseaux visibles par cet appareil, position approximative seulement.</p></div></div>
<div class="meta-row"><span class="risk-badge">observation</span><span class="status-badge">radio</span></div>
<form method="post" action="/recon">{self._token()}<input type="hidden" name="source_wifi" value="1">
<input type="hidden" name="subject" value="wifi-local">{view_select}{consent}{keep}
<button type="submit">LANCER</button></form></article>

<article class="scanner-card"><div class="tool-head"><span class="quick-icon">BT</span>
<div><h3>Bluetooth Radar</h3><p class="muted">Appareils connus ou visibles selon ce que l'OS expose.</p></div></div>
<div class="meta-row"><span class="risk-badge">observation</span><span class="status-badge">proximité</span></div>
<form method="post" action="/recon">{self._token()}<input type="hidden" name="source_bluetooth" value="1">
<input type="hidden" name="subject" value="bluetooth-local">{view_select}{consent}{keep}
<button type="submit">LANCER</button></form></article>

<article class="scanner-card"><div class="tool-head"><span class="quick-icon">TCP</span>
<div><h3>Scan ports autorisé</h3><p class="muted">Ports TCP sur une cible privée ou explicitement autorisée.</p></div></div>
<div class="meta-row"><span class="risk-badge">autorisé</span><span class="status-badge">service</span></div>
<form method="post" action="/recon">{self._token()}<input type="hidden" name="source_ports" value="1">
<input type="hidden" name="subject" value="{target_value}">
<label>Cible<input name="target" value="{target_value}" placeholder="192.168.1.25 ou localhost"></label>
<label>Ports<input name="ports" value="{ports_value}" placeholder="22,80,443 ou 1-1024"></label>
{view_select}{consent}{keep}<button type="submit">LANCER</button></form></article>

<article class="scanner-card"><div class="tool-head"><span class="quick-icon">HTTP</span>
<div><h3>Site public passif</h3><p class="muted">Lecture des en-têtes HTTP sans injection ni fuzzing.</p></div></div>
<div class="meta-row"><span class="risk-badge">passif</span><span class="status-badge">web</span></div>
<form method="post" action="/recon">{self._token()}<input type="hidden" name="source_http" value="1">
<input type="hidden" name="subject" value="{target_value}">
<label>URL ou hôte<input name="target" value="{target_value}" placeholder="https://example.org"></label>
{view_select}{consent}{keep}<button type="submit">LANCER</button></form></article>

<article class="scanner-card"><div class="tool-head"><span class="quick-icon">PKT</span>
<div><h3>Packet Observer</h3><p class="muted">Préparation d'une vue pédagogique type mini Wireshark.</p></div></div>
<div class="meta-row"><span class="risk-badge">lecture</span><span class="status-badge">à venir</span></div>
<p class="muted">La capture trafic sera limitée au lab/local autorisé et ne tentera jamais de déchiffrer HTTPS.</p>
<a class="button" href="/tools">VOIR OUTILS</a></article>
</div></section>

<section class="card full"><details><summary><strong>Combiner plusieurs sources</strong></summary>
<form method="post" action="/recon">{self._token()}
<div class="quick-grid">
<label class="quick-toggle"><input type="checkbox" name="source_discover"{checked("source_discover")}>
<span class="quick-icon">IP</span><strong>Réseau IP</strong><span>Hôtes actifs</span></label>
<label class="quick-toggle"><input type="checkbox" name="source_ports"{checked("source_ports")}>
<span class="quick-icon">TCP</span><strong>Ports TCP</strong><span>Services ouverts</span></label>
<label class="quick-toggle"><input type="checkbox" name="source_wifi"{checked("source_wifi")}>
<span class="quick-icon">WIFI</span><strong>Wi-Fi</strong><span>Réseaux visibles</span></label>
<label class="quick-toggle"><input type="checkbox" name="source_bluetooth"{checked("source_bluetooth")}>
<span class="quick-icon">BT</span><strong>Bluetooth</strong><span>Inventaire OS</span></label>
<label class="quick-toggle"><input type="checkbox" name="source_http"{checked("source_http")}>
<span class="quick-icon">HTTP</span><strong>HTTP</strong><span>En-têtes passifs</span></label>
</div><input type="hidden" name="subject" value="{subject_value}">
<div class="recon-fields"><label data-recon-field="network">Réseau local autorisé
<input name="network" value="{network_value}" placeholder="192.168.1.0/24"></label>
<label data-recon-field="target">Cible IP, nom local ou URL
<input name="target" value="{target_value}" placeholder="192.168.1.25 ou http://192.168.1.25"></label>
<label data-recon-field="ports">Ports
<input name="ports" value="{ports_value}" placeholder="22,80,443 ou 1-1024"></label></div>
{view_select}{consent}{keep}<button type="submit">EXÉCUTER LA RECON COMBINÉE</button></form></details></section>

<section class="card full"><h2>Conditions</h2><ul class="clean">
<li>IP/ports : uniquement réseau privé, localhost ou cible explicitement autorisée.</li>
<li>Wi-Fi : nécessite les droits système/localisation selon Windows, Linux ou Termux.</li>
<li>Bluetooth : inventaire OS uniquement, sans appairage ni interaction active.</li>
<li>HTTP : lecture passive d'en-têtes sur une URL fournie.</li>
<li>Trafic : lecture pédagogique prévue, sans déchiffrement HTTPS.</li></ul></section>
{self._result("/recon")}</div>"""
        self._send(render_layout("Scanner", body))

    def _run_recon(self, data: dict[str, list[str]]) -> None:
        self._clear()
        started = time.monotonic()
        try:
            settings = load_settings()
            self.state.recon_form = {
                "source_discover": _checked(data, "source_discover"),
                "source_ports": _checked(data, "source_ports"),
                "source_wifi": _checked(data, "source_wifi"),
                "source_bluetooth": _checked(data, "source_bluetooth"),
                "source_http": _checked(data, "source_http"),
                "authorized": _checked(data, "authorized"),
                "keep": _checked(data, "keep"),
                "subject": _field(data, "subject"),
                "network": _field(data, "network"),
                "target": _field(data, "target"),
                "ports": _field(data, "ports", settings.default_ports),
                "view": _field(data, "view", "category"),
            }
            if not _checked(data, "authorized"):
                raise ValueError("L'autorisation explicite est obligatoire.")
            subject = _field(data, "subject")
            network_subject = _field(data, "network") or subject
            target_subject = _field(data, "target") or subject
            view = _field(data, "view", "category")
            categories: dict[str, dict[str, Any]] = {}
            suggestions: list[str] = []
            ran_any = False
            if _checked(data, "source_discover"):
                if not network_subject:
                    raise ValueError("Indiquez un réseau privé pour la découverte IP.")
                results, engine = discover_hosts(network_subject, settings.prefer_nmap)
                categories["network"] = {"title": "Réseau IP", "engine": engine, "items": results}
                suggestions.append("Sélectionner une IP découverte puis ouvrir Profiler ou Scanner ports.")
                ran_any = True
                if _checked(data, "keep"):
                    save_history("discovery", network_subject, engine, results)
            if _checked(data, "source_ports"):
                if not target_subject:
                    raise ValueError("Indiquez une cible privée pour le scan de ports.")
                from .safety import parse_ports

                ports = _field(data, "ports", settings.default_ports)
                results, engine = scan_ports(
                    target_subject,
                    parse_ports(ports),
                    settings.scan_timeout,
                    settings.prefer_nmap,
                )
                categories["ports"] = {
                    "title": "Ports TCP",
                    "engine": engine,
                    "items": [{"address": target_subject, **item} for item in results],
                }
                suggestions.append("Ouvrir HTTP pour les ports web ou Profiler pour consolider l'actif.")
                ran_any = True
                if _checked(data, "keep"):
                    save_history("port_scan", target_subject, engine, results, ports=ports)
            if _checked(data, "source_wifi"):
                wifi = wifi_scan()
                categories["wifi"] = {
                    "title": "Wi-Fi visible",
                    "engine": str(wifi.get("engine", "")),
                    "description": str(wifi.get("description", "")),
                    "limitations": wifi.get("limitations", []),
                    "items": wifi.get("networks", []),
                }
                suggestions.append("Contrôler le chiffrement Wi-Fi et documenter les réseaux ouverts ou faibles.")
                ran_any = True
            if _checked(data, "source_bluetooth"):
                bluetooth = bluetooth_inventory()
                categories["bluetooth"] = {
                    "title": "Bluetooth",
                    "engine": str(bluetooth.get("engine", "")),
                    "description": str(bluetooth.get("description", "")),
                    "limitations": bluetooth.get("limitations", []),
                    "items": bluetooth.get("items", []),
                }
                suggestions.append("Profiler uniquement les appareils Bluetooth explicitement autorisés.")
                ran_any = True
            if _checked(data, "source_http"):
                if not target_subject:
                    raise ValueError("Indiquez une URL pour l'analyse HTTP passive.")
                url = target_subject if "://" in target_subject else f"http://{target_subject}"
                status, headers = fetch_headers(url)
                categories["http"] = {
                    "title": "HTTP",
                    "engine": f"HEAD {status}",
                    "items": analyze_headers(headers, url.startswith("https://")),
                }
                suggestions.append("Ouvrir l'audit HTTP détaillé pour conserver la cible et les en-têtes.")
                ran_any = True
            if not ran_any:
                raise ValueError("Activez au moins une source de reconnaissance.")
            records = {"artifacts": [], "events": [], "correlations": []}
            if _checked(data, "keep"):
                records = save_recon_records(
                    categories,
                    subject=target_subject or network_subject,
                    scope="local_authorized",
                )
            self.state.result_title = "Résultat de reconnaissance"
            self.state.result_route = "/recon"
            self.state.result = {
                "subject": target_subject or network_subject,
                "network": network_subject,
                "target": target_subject,
                "view": view,
                "duration_seconds": round(time.monotonic() - started, 2),
                "categories": categories,
                "suggestions": suggestions,
                "records": {
                    "artifacts": len(records["artifacts"]),
                    "events": len(records["events"]),
                    "correlations": len(records["correlations"]),
                },
            }
        except (ValueError, OSError) as exc:
            self.state.error = str(exc)
        self._redirect("/recon")

    def _profile(self) -> None:
        settings = load_settings()
        devices = _device_cards()
        body = f"""<div class="grid"><section class="card full">
<span class="eyebrow">Inventaire</span><h2>Appareils observes</h2>
<p class="muted">Liste compacte construite depuis les scans conserves et les artefacts JSON.
Les hypotheses restent techniques et peuvent etre faibles si peu d'indices sont disponibles.</p>
{devices}</section><section class="card wide">
<h2>Creer une fiche appareil</h2><p class="muted">Le scan est limite aux adresses
privees et locales. Nmap est utilise s'il est disponible.</p>
<form method="post" action="/profile">{self._token()}
<label>Cible<input name="target" placeholder="192.168.1.25 ou localhost" required></label>
<label>Ports<input name="ports" value="{escape(settings.default_ports)}" required></label>
<label class="check"><input type="checkbox" name="authorized" required>
Je dispose de l'autorisation du proprietaire ou responsable.</label>
<label class="check"><input type="checkbox" name="keep" checked>Conserver la fiche en artefact/timeline.</label>
<label class="check"><input type="checkbox" name="report">Generer un rapport.</label>
<button type="submit">LANCER LE PROFIL</button></form></section>
<section class="card"><h2>Filtres rapides</h2><div class="app-grid">
<a class="app" href="/devices"><strong>Actifs</strong><span>Appareils vus recemment</span></a>
<a class="app" href="/reports"><strong>Inconnus</strong><span>Confiance faible a correler</span></a>
<a class="app" href="/reports"><strong>Critiques</strong><span>Ports sensibles ou alertes</span></a>
<a class="app" href="/reports"><strong>Favoris</strong><span>A brancher aux missions</span></a>
</div></section>
{self._result("/profile")}</div>"""
        self._send(render_layout("Appareils", body))

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
            if _checked(data, "keep"):
                sensitive_ports = {21, 23, 445, 3389, 5900, 6379}
                has_sensitive_port = False
                for item in profile.services:
                    try:
                        has_sensitive_port = int(item.get("port", 0)) in sensitive_ports
                    except (TypeError, ValueError):
                        has_sensitive_port = False
                    if has_sensitive_port:
                        break
                artifact = Artifact(
                    kind="device_profile",
                    source=str(profile.scan_engine or "profiler"),
                    title=f"Profil {profile.address}",
                    summary=f"{profile.address} : {profile.device_type} ({profile.confidence})",
                    value=profile.address,
                    confidence=profile.confidence,
                    risk="attention" if has_sensitive_port else "info",
                    scope="local_authorized",
                    tags=["device", "profile"],
                    data=result,
                )
                save_record(artifact)
                save_record(
                    TimelineEvent(
                        source="profiler",
                        event_type="device_profile",
                        description=artifact.summary,
                        level="attention" if artifact.risk == "attention" else "info",
                        artifact_id=artifact.id,
                        link="/devices",
                    )
                )
                result["artefact"] = artifact.id
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

        def record_items(record_type: str, scope: str) -> str:
            items = []
            for path in list_records(record_type):
                payload = load_record(path)
                label = record_display_name(payload)
                items.append(
                    f"""<li><strong>{escape(label)}</strong><div class="data-actions">
<form class="compact" method="post" action="/data"
data-confirm="Supprimer dÃ©finitivement cet Ã©lÃ©ment ?">{self._token()}
<input type="hidden" name="scope" value="{scope}">
<input type="hidden" name="name" value="{escape(path.name)}">
<input type="hidden" name="operation" value="delete">
<button class="danger" type="submit">SUPPRIMER</button></form></div></li>"""
                )
            return "".join(items) or "<li class='muted'>Aucune donnee disponible.</li>"

        artifact_items = record_items("artifact", "artifact")
        event_items = record_items("event", "event")
        correlation_items = record_items("correlation", "correlation")

        delete_all = f"""<form method="post" action="/data"
data-confirm="Supprimer tous les rapports, historiques et missions ? Cette action est irréversible.">
{self._token()}<input type="hidden" name="scope" value="all">
<input type="hidden" name="operation" value="delete_all">
<button class="danger" type="submit">TOUT SUPPRIMER</button></form>"""
        body = f"""{feedback}<section class="card full" data-tabs>
<h2>Rapports et preuves locales</h2><p class="muted">Consultez, renommez ou supprimez les
éléments stockés par recon SC.</p><div class="tabs">
<button class="tab-button active" type="button" data-tab="reports">Rapports</button>
<button class="tab-button" type="button" data-tab="history">Historiques</button>
<button class="tab-button" type="button" data-tab="artifacts">Artefacts</button>
<button class="tab-button" type="button" data-tab="timeline">Timeline</button>
<button class="tab-button" type="button" data-tab="correlations">CorrÃ©lations</button>
<button class="tab-button" type="button" data-tab="missions">Missions</button>
<button class="tab-button" type="button" data-tab="cleanup">Nettoyage</button></div>
<div class="tab-panel active" data-panel="reports"><ul class="clean">{report_items}</ul></div>
<div class="tab-panel" data-panel="history"><ul class="clean">{histories}</ul></div>
<div class="tab-panel" data-panel="artifacts">{_artifact_board()}<h3>Gestion</h3><ul class="clean">{artifact_items}</ul></div>
<div class="tab-panel" data-panel="timeline">{_timeline_board()}<h3>Gestion</h3><ul class="clean">{event_items}</ul></div>
<div class="tab-panel" data-panel="correlations">{_correlation_board()}<h3>Gestion</h3><ul class="clean">{correlation_items}</ul></div>
<div class="tab-panel" data-panel="missions"><ul class="clean">{mission_items}</ul></div>
<div class="tab-panel" data-panel="cleanup"><div class="notice error">
Cette action efface toutes les données générées, mais pas le code du projet.</div>
{delete_all}</div></section>"""
        self._send(render_layout("Rapports", body))

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
                delete_all_records()
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
            elif scope in {"artifact", "event", "correlation"}:
                path = self._stored_path(list_records(scope), name)
                if operation == "delete":
                    delete_record(path)
                    self.state.message = "Donnee structuree supprimee."
                else:
                    raise ValueError("Action de donnee structuree inconnue.")
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
<span class="eyebrow">Local exposure index</span><h2>Inventaire d'exposition local</h2>
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
<div class="geo-tools"><section class="geo-tool"><h3>Position</h3>
<div class="geo-tool-row"><input id="map-latitude" type="number" step="any"
placeholder="Latitude"><input id="map-longitude" type="number" step="any"
placeholder="Longitude"></div><div class="geo-tool-row"><select id="map-layer" aria-label="Fond de carte">
<option value="standard">Standard</option>
<option value="topographic">Topographique / relief</option>
</select><select id="map-zoom" aria-label="Niveau de zoom">
<option value="2">2</option><option value="3">3</option><option value="4">4</option>
<option value="5">5</option><option value="6">6</option><option value="7">7</option>
<option value="8">8</option><option value="9">9</option><option value="10">10</option>
<option value="11">11</option><option value="12">12</option><option value="13">13</option>
<option value="14">14</option><option value="15">15</option>
<option value="16" selected>16</option><option value="17">17</option>
<option value="18">18</option><option value="19">19</option>
</select></div><div class="geo-actions"><button type="button"
onclick="showGeoMap(document.getElementById('map-latitude').value,
document.getElementById('map-longitude').value)">AFFICHER</button>
<button type="button" onclick="locateMap()">UTILISER MA POSITION</button></div></section>
<section class="geo-tool"><h3>Adresse</h3>
<div class="geo-tool-row single"><input id="map-search" placeholder="Rechercher une adresse"></div>
<div class="geo-actions"><button type="button" onclick="searchMapAddress()">RECHERCHER</button></div></section>
<section class="geo-tool"><h3>Trajet</h3>
<div class="geo-tool-row"><select id="route-start-mode" aria-label="Départ">
<option value="current">Depart : marqueur actuel</option><option value="custom">Depart : adresse</option>
</select><input id="route-start" placeholder="Adresse de départ si différente"></div>
<div class="geo-tool-row"><input id="route-end" placeholder="Destination"><select id="route-profile" aria-label="Mode de trajet">
<option value="driving">Voiture</option><option value="cycling">Vélo</option>
<option value="walking">À pied</option></select></div>
<div class="geo-actions"><button type="button" onclick="routeFromMap()">CALCULER UN TRAJET</button></div></section></div>
<p id="geo-map-status" class="muted">Aucune position demandée.</p>
<div class="geo-map-shell"><div class="geo-map" id="geo-map-frame" role="img"
aria-label="Carte centrée sur la position choisie"></div>
<div class="map-ui" aria-label="Contrôles de carte">
<button type="button" title="Zoom avant" onclick="adjustGeoZoom(1)">+</button>
<button type="button" title="Recentrer sur le marqueur" onclick="recenterGeoMap()">@</button>
<button type="button" title="Zoom arrière" onclick="adjustGeoZoom(-1)">-</button>
</div></div>
<p class="muted">Molette ou pincement : zoom. Fond actif : <span id="map-attribution">aucun</span>. Données ©
<a href="https://www.openstreetmap.org/copyright" target="_blank"
rel="noreferrer">contributeurs OpenStreetMap</a>. Relief :
<a href="https://opentopomap.org/" target="_blank"
rel="noreferrer">OpenTopoMap</a>.</p></div>
<div class="tab-panel" data-panel="network">{render_topology()}
<p class="muted">Vert : actif observé. Orange : service à vérifier. Cette vue
est une topologie technique schématique, sans localisation physique.</p></div>
</section></div>"""
        self._send(render_layout("Carte", body))

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
            ("core", "SC", "#79ff3d"),
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
<span class="switch-track"></span></label>
<label>Opacité du verre
<span class="range-row"><input type="range" name="glass_opacity" min="0.15" max="0.95"
step="0.05" value="{settings.glass_opacity:.2f}">
<strong id="glass-opacity-value">{settings.glass_opacity:.2f}</strong></span></label>
<fieldset class="mode-slider"><legend>Mode global</legend><div class="mode-track" data-mode-track="app" data-value="{settings.app_color_mode}">
<label><input type="radio" name="app_color_mode" value="auto"{" checked" if settings.app_color_mode == "auto" else ""}><span>Auto</span></label>
<label><input type="radio" name="app_color_mode" value="light"{" checked" if settings.app_color_mode == "light" else ""}><span>Clair</span></label>
<label><input type="radio" name="app_color_mode" value="dark"{" checked" if settings.app_color_mode == "dark" else ""}><span>Sombre</span></label>
</div></fieldset>
<fieldset class="mode-slider"><legend>Mode carte</legend><div class="mode-track" data-mode-track="map" data-value="{settings.map_color_mode}">
<label><input type="radio" name="map_color_mode" value="auto"{" checked" if settings.map_color_mode == "auto" else ""}><span>Auto</span></label>
<label><input type="radio" name="map_color_mode" value="day"{" checked" if settings.map_color_mode == "day" else ""}><span>Jour</span></label>
<label><input type="radio" name="map_color_mode" value="night"{" checked" if settings.map_color_mode == "night" else ""}><span>Nuit</span></label>
</div></fieldset></div>
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
                theme=_field(data, "theme", "core"),
                app_color_mode=_field(data, "app_color_mode", "auto"),
                map_color_mode=_field(data, "map_color_mode", "auto"),
                glass_effect=_checked(data, "glass_effect"),
                glass_opacity=float(_field(data, "glass_opacity", "0.46")),
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
            "https://*.tile.opentopomap.org; "
            "connect-src 'self' https://nominatim.openstreetmap.org https://router.project-osrm.org; "
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

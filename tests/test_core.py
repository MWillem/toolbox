import io
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
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
from cybertoolbox.labs.cracking import (
    crack_demo_hash,
    crack_wpa2_demo,
    derive_wpa2_pmk,
)
from cybertoolbox.labs.payloads import analyze_payload_file, create_harmless_payload
from cybertoolbox.labs.script_analysis import analyze_script
from cybertoolbox.labs.wireless import (
    _parse_netsh_interface,
    _parse_netsh_scan,
    _parse_nmcli_scan,
    _parse_termux_scan,
    wireless_diagnostics,
    wifi_scan,
    wifi_security_lesson,
)
from cybertoolbox.device_profile import infer_device_type
from cybertoolbox.history import (
    compare_port_scans,
    delete_all_history,
    list_history,
    load_history,
    rename_history,
    save_history,
)
from cybertoolbox.mission import service_recommendations
from cybertoolbox.reports import (
    delete_all_reports,
    export_report,
    rename_report,
    save_professional_report,
)
from cybertoolbox.safety import parse_ports, parse_private_network, resolve_authorized_target
from cybertoolbox.settings import Settings, load_settings, save_settings
from cybertoolbox.watchdog import (
    WatchdogOperation,
    answer_matches,
    contains_expected_indicators,
)
from cybertoolbox.webapp import _value, _workspace_path, render_layout, render_topology
from cybertoolbox.cli import print_menu_item, responsive_banner
from cybertoolbox.context_info import local_context


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
        self.assertIn('id="loading-overlay"', page)
        self.assertIn('id="menu-toggle"', page)
        self.assertIn('data-theme="', page)

    def test_structured_lists_use_one_aligned_table(self):
        rendered = _value(
            [
                {"address": "192.168.1.5", "hostname": "alpha.home"},
                {"address": "192.168.1.27", "hostname": "beta.home"},
            ]
        )
        self.assertEqual(rendered.count("class='data-table'"), 1)
        self.assertEqual(rendered.count("<th>address</th>"), 1)
        self.assertEqual(rendered.count("<th>hostname</th>"), 1)
        self.assertEqual(rendered.count("<tbody>"), 1)

    def test_terminal_banner_becomes_compact_on_small_screens(self):
        with patch("cybertoolbox.cli.terminal_width", return_value=40):
            self.assertEqual(responsive_banner("large", "compact"), "compact")
        with patch("cybertoolbox.cli.terminal_width", return_value=100):
            self.assertEqual(responsive_banner("large", "compact"), "large")

    def test_menu_numbers_are_aligned(self):
        output = io.StringIO()
        with patch("cybertoolbox.cli.terminal_width", return_value=80):
            with redirect_stdout(output):
                print_menu_item("1", "Premier")
                print_menu_item("10", "Dixième")
        self.assertEqual(output.getvalue().splitlines(), [" 1. Premier", "10. Dixième"])

    def test_dashboard_context_and_topology_render(self):
        context = local_context()
        self.assertIn("timezone", context)
        self.assertIn("time", context)
        topology = render_topology()
        self.assertIn("<svg", topology)
        self.assertIn("TOOLBOX", topology)

    def test_gui_file_analysis_stays_inside_workspace(self):
        self.assertEqual(_workspace_path("README.md").name, "README.md")
        with self.assertRaises(ValueError):
            _workspace_path(str(Path.home().parent))


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

    def test_wpa2_offline_lab_finds_demo_password(self):
        target = derive_wpa2_pmk("CTOS-LAB", "classe-2026")
        result = crack_wpa2_demo(
            "CTOS-LAB",
            target,
            ["motdepasse", "classe-2026", "autre-secret"],
        )
        self.assertEqual(result["found"], "classe-2026")
        self.assertEqual(result["tested"], 2)

    def test_wifi_parsers_return_common_shape(self):
        nmcli = _parse_nmcli_scan(
            r"Lab\:Wifi:AA\:BB\:CC\:DD\:EE\:FF:6:2437:80:WPA2"
        )
        netsh = _parse_netsh_scan(
            "SSID 1 : Classe\n"
            "    Authentication : WPA2-Personal\n"
            "    BSSID 1 : aa:bb:cc:dd:ee:ff\n"
            "         Signal : 90%\n"
            "         Channel : 11\n"
            "SSID 2 : Invites\n"
            "    Authentication : Open\n"
            "    BSSID 1 : 11:22:33:44:55:66\n"
            "         Signal : 55%\n"
            "         Channel : 1\n"
        )
        termux = _parse_termux_scan(
            '[{"ssid":"MobileLab","bssid":"11:22:33:44:55:66",'
            '"frequency_mhz":2412,"rssi":-45,"capabilities":"[WPA2-PSK]"}]'
        )
        for result in (nmcli, termux):
            self.assertEqual(len(result), 1)
            self.assertIn("ssid", result[0])
            self.assertIn("security", result[0])
        self.assertEqual(len(netsh), 2)
        self.assertEqual(netsh[1]["ssid"], "Invites")
        self.assertEqual(nmcli[0]["ssid"], "Lab:Wifi")
        self.assertEqual(termux[0]["channel"], 1)

    def test_windows_connected_wifi_is_normalized(self):
        connected = _parse_netsh_interface(
            "    SSID                   : Freebox-C81246\n"
            "    BSSID                  : aa:bb:cc:dd:ee:ff\n"
            "    Authentification       : WPA2-Personnel\n"
            "    Signal                 : 86%\n"
            "    Canal                  : 6\n"
        )
        self.assertIsNotNone(connected)
        self.assertEqual(connected["ssid"], "Freebox-C81246")
        self.assertEqual(connected["channel"], "6")
        self.assertTrue(connected["connected"])

    def test_windows_wifi_scan_explains_location_fallback(self):
        interface = (
            "SSID : Freebox-C81246\n"
            "BSSID : aa:bb:cc:dd:ee:ff\n"
            "Authentification : WPA2-Personnel\n"
            "Signal : 86%\n"
            "Canal : 6\n"
        )
        with patch("cybertoolbox.labs.wireless.platform.system", return_value="Windows"):
            with patch("cybertoolbox.labs.wireless.shutil.which", return_value=None):
                with patch(
                    "cybertoolbox.labs.wireless._run",
                    side_effect=[
                        {
                            "available": False,
                            "output": "Autorisation de localisation nécessaire",
                            "error": "Autorisation de localisation nécessaire",
                        },
                        {"available": True, "output": interface, "error": ""},
                    ],
                ):
                    result = wifi_scan()
        self.assertFalse(result["scan_complete"])
        self.assertEqual(result["networks"][0]["ssid"], "Freebox-C81246")
        self.assertTrue(any("localisation" in item.lower() for item in result["limitations"]))

    def test_wireless_diagnostics_returns_capabilities(self):
        result = wireless_diagnostics()
        self.assertIn("platform", result)
        self.assertIn("wifi_scan_available", result)

    def test_wifi_security_lesson_flags_open_networks(self):
        self.assertTrue(any("ouvert" in item.lower() for item in wifi_security_lesson("OPEN")))

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
            expected = Settings(
                language="en",
                report_mode="off",
                theme="github",
                glass_effect=False,
                default_ports="22,80",
            )
            save_settings(expected, path)
            loaded = load_settings(path)
            self.assertEqual(loaded.language, "en")
            self.assertEqual(loaded.report_mode, "off")
            self.assertEqual(loaded.theme, "github")
            self.assertFalse(loaded.glass_effect)
            self.assertEqual(loaded.default_ports, "22,80")

    def test_scan_history_is_versioned_renamed_and_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = save_history(
                "port_scan",
                "192.168.1.10",
                "test",
                [{"port": 22, "service": "ssh"}],
                ports="22,80",
                root=root,
            )
            second = save_history(
                "port_scan",
                "192.168.1.10",
                "test",
                [{"port": 80, "service": "http"}],
                ports="22,80",
                root=root,
            )
            self.assertNotEqual(first, second)
            rename_history(first, "Serveur de test", root)
            self.assertEqual(load_history(first, root)["label"], "Serveur de test")
            self.assertEqual(len(list_history("port_scan", root)), 2)
            self.assertEqual(delete_all_history("port_scan", root), 2)
            self.assertEqual(list_history(root=root), [])

    def test_port_scan_comparison_reports_changes(self):
        previous = {
            "results": [
                {"port": 22, "service": "ssh"},
                {"port": 80, "service": "http"},
            ]
        }
        changes = compare_port_scans(
            previous,
            [
                {"port": 22, "service": "openssh"},
                {"port": 443, "service": "https"},
            ],
        )
        self.assertTrue(any("443/tcp" in item for item in changes["opened"]))
        self.assertTrue(any("80/tcp" in item for item in changes["closed"]))
        self.assertTrue(any("22/tcp" in item for item in changes["changed"]))

    def test_reports_can_be_renamed_and_deleted_together(self):
        with tempfile.TemporaryDirectory() as directory:
            from cybertoolbox import reports

            previous = reports.REPORTS_DIR
            reports.REPORTS_DIR = Path(directory)
            try:
                report = reports.save_report("Original", [("Test", "Contenu")])
                renamed = rename_report(report, "nouveau-nom")
                renamed.with_suffix(".html").write_text("export", encoding="utf-8")
                self.assertEqual(renamed.name, "nouveau-nom.md")
                self.assertEqual(delete_all_reports(), 2)
                self.assertEqual(list(Path(directory).iterdir()), [])
            finally:
                reports.REPORTS_DIR = previous


if __name__ == "__main__":
    unittest.main()

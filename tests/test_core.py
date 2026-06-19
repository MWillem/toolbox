import io
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from pathlib import Path

from cybertoolbox.labs.hashing import hash_file, hash_text
from cybertoolbox.labs.hash_advanced import (
    crack_hash as crack_advanced_hash,
    hash_generate,
    hash_ntlm,
    identify_hash,
)
from cybertoolbox.labs.bluetooth_advanced import (
    OUI_MANUFACTURERS,
    lookup_manufacturer,
)
from cybertoolbox.labs.nfc_tools import clone_tag, parse_ndef_record
from cybertoolbox.labs.qr_tools import decode_qr_wifi, generate_qr_text
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
from cybertoolbox.labs.packet_observer import observe_packets
from cybertoolbox.labs.public_exposure import inspect_public_exposure
from cybertoolbox.labs.script_analysis import analyze_script
from cybertoolbox.labs.wireless import (
    _normalize_bluetooth_items,
    _normalize_wifi_networks,
    _parse_netsh_interface,
    _parse_netsh_scan,
    _parse_nmcli_scan,
    _parse_termux_scan,
    mobile_operator_info,
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
from cybertoolbox.mission import create_mission_from_template, mission_templates, service_recommendations
from cybertoolbox.reports import (
    delete_all_reports,
    export_report,
    rename_report,
    save_professional_report,
)
from cybertoolbox.records import (
    Artifact,
    delete_all_records,
    generate_correlations_from_records,
    list_records,
    load_record,
    records_summary,
    save_record,
    save_recon_records,
)
from cybertoolbox.safety import parse_ports, parse_private_network, resolve_authorized_target
from cybertoolbox.settings import Settings, load_settings, save_settings
from cybertoolbox.watchdog import (
    WatchdogOperation,
    answer_matches,
    contains_expected_indicators,
)
from cybertoolbox.webapp import _nfc_payload, _qr_payload, _value, _workspace_path, render_layout, render_topology
from cybertoolbox.cli import interactive_menu, print_menu_item, responsive_banner
from cybertoolbox.context_info import local_context
from cybertoolbox.enrich_profile import calculate_digital_shadow_score


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
        self.assertIn('class="home-link"', page)
        self.assertIn('back-button icon-button', page)
        self.assertNotIn('id="menu-toggle"', page)
        self.assertIn('data-theme="', page)
        self.assertIn('data-app-mode="', page)
        self.assertIn('data-map-mode="', page)
        self.assertIn("Maréchaux Willem", page)
        self.assertIn("recon SC", page)
        self.assertIn("Accueil", page)
        self.assertNotIn("SOURCE CORE", page)
        self.assertNotIn("DROP", page)
        self.assertIn("mapProviders", page)
        self.assertIn("map-ui", page)
        self.assertIn("searchMapAddress", page)
        self.assertIn("routeFromMap", page)
        self.assertIn("recenterGeoMap", page)
        self.assertIn("router.project-osrm.org", page)
        self.assertIn("pointermove", page)
        self.assertIn('class="shell nav-collapsed"', page)
        self.assertIn("OpenTopoMap", page)
        self.assertIn("[name=glass_opacity]", page)
        self.assertIn("[name=app_color_mode]", page)
        self.assertIn("[name=map_color_mode]", page)
        self.assertIn("mode-track", page)
        self.assertIn("page-actions", page)
        self.assertIn("result-modal", page)
        self.assertIn("dashboard-pages", page)
        self.assertIn("data-size-cycle", page)
        self.assertIn("data-layout-action", page)
        self.assertIn("data-dashboard-reset", page)
        self.assertIn('data-mode-track="app"', page)
        self.assertIn('data-mode-track="map"', page)
        self.assertIn("quick-toggle", page)
        self.assertIn("scanner-grid", page)
        self.assertIn("scanner-card", page)
        self.assertIn("device-card", page)
        self.assertIn("profile-section", page)
        self.assertIn("record-card", page)
        self.assertIn("filter-row", page)
        self.assertIn("wireless-grid", page)
        self.assertIn("radarSweep", page)
        self.assertNotIn("CyclOSM", page)
        self.assertNotIn("Humanitarian OpenStreetMap", page)
        self.assertIn("await fetch", page)

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

    def test_ctrl_c_can_return_to_the_main_menu(self):
        answers = iter(["o", KeyboardInterrupt(), "n", "0"])

        def answer(*_args):
            value = next(answers)
            if isinstance(value, BaseException):
                raise value
            return value

        with patch("builtins.input", side_effect=answer):
            with patch("cybertoolbox.cli.clear_screen"):
                self.assertEqual(interactive_menu(), 0)

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

    def test_advanced_hash_generation_identification_and_cracking(self):
        self.assertEqual(hash_generate("abc", "md5"), "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(hash_ntlm("password"), "8846f7eaee8fb117ad06bdd830b7586c")
        identified = identify_hash("5d41402abc4b2a76b9719d911017c592")
        self.assertEqual(
            {item["algorithm"] for item in identified},
            {"md5", "ntlm"},
        )
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "words.txt"
            wordlist.write_text("admin\nbonjour\nsecret\n", encoding="utf-8")
            result = crack_advanced_hash(
                hash_generate("bonjour", "sha256"),
                str(wordlist),
                "auto",
            )
        self.assertTrue(result["found"])
        self.assertEqual(result["password"], "bonjour")

    def test_qr_wifi_decoder_and_ascii_generator(self):
        decoded = decode_qr_wifi("WIFI:T:WPA;S:Classe;P:secret;;")
        self.assertEqual(decoded["ssid"], "Classe")
        self.assertEqual(decoded["password"], "secret")
        self.assertIn("██", generate_qr_text("CyberToolbox"))

    def test_qr_payload_flags_plain_http_urls(self):
        result = _qr_payload({"qr_mode": ["url"], "qr_text": ["http://example.org"]})
        self.assertEqual(result["mode"], "qr_tool")
        self.assertEqual(result["content"]["type"], "url")
        self.assertEqual(result["risk"]["level"], "attention")
        self.assertIn("HTTP", result["risk"]["reason"])

    def test_ndef_text_and_documentary_clone(self):
        raw = bytes([0xD1, 0x01, 0x05]) + b"T" + bytes([0x02]) + b"frOK"
        parsed = parse_ndef_record(raw)
        self.assertEqual(parsed["kind"], "text")
        self.assertEqual(parsed["value"], "OK")
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "tag.json"
            self.assertTrue(clone_tag("01:02:03:04", parsed, str(destination)))
            self.assertTrue(destination.exists())

    def test_nfc_payload_decodes_lab_ndef_hex(self):
        result = _nfc_payload({"nfc_mode": ["parse_hex"], "value": ["D10105540266724F4B"]})
        self.assertEqual(result["mode"], "nfc_tool")
        self.assertEqual(result["result"]["kind"], "text")
        self.assertEqual(result["result"]["value"], "OK")
        self.assertTrue(any("Aucun clonage" in item for item in result["limitations"]))

    def test_bluetooth_oui_table_and_lookup(self):
        manufacturers = set(OUI_MANUFACTURERS.values())
        self.assertGreaterEqual(len(manufacturers), 50)
        self.assertEqual(lookup_manufacturer("00:00:0C:12:34:56"), "Cisco")
        self.assertEqual(
            lookup_manufacturer("12:34:56:78:9A:BC"),
            "Fabricant inconnu",
        )

    def test_digital_shadow_score(self):
        result = calculate_digital_shadow_score(
            {
                "services": [{"port": 22}] * 4,
                "mac": "00:11:22:33:44:55",
                "hostname": "lab",
                "manufacturer": "Demo",
                "found_sites": [{"site": "GitHub"}],
                "location": {"country": "FR"},
            }
        )
        self.assertEqual(result["score"], 70)
        self.assertEqual(result["risk_level"], "high")

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
            "    Encryption : CCMP\n"
            "    BSSID 1 : aa:bb:cc:dd:ee:ff\n"
            "         Signal : 90%\n"
            "         Channel : 11\n"
            "SSID 2 : Invites\n"
            "    Authentication : Open\n"
            "    BSSID 1 : 11:22:33:44:55:66\n"
            "         Signal : 55%\n"
            "         Channel : 1\n"
            "Nom SSID : Freebox-19ACF0\n"
            "    Authentification : WPA2-Personnel\n"
            "    BSSID 1 : 22:33:44:55:66:77\n"
            "         Signal : 75%\n"
            "         Canal : 6\n"
        )
        termux = _parse_termux_scan(
            '[{"ssid":"MobileLab","bssid":"11:22:33:44:55:66",'
            '"frequency_mhz":2412,"rssi":-45,"capabilities":"[WPA2-PSK]"}]'
        )
        for result in (nmcli, termux):
            self.assertEqual(len(result), 1)
            self.assertIn("ssid", result[0])
            self.assertIn("security", result[0])
        self.assertEqual(len(netsh), 3)
        self.assertEqual(netsh[1]["ssid"], "Invites")
        self.assertEqual(netsh[2]["ssid"], "Freebox-19ACF0")
        self.assertEqual(netsh[0]["security"], "WPA2-Personal / CCMP")
        self.assertEqual(nmcli[0]["ssid"], "Lab:Wifi")
        self.assertEqual(termux[0]["channel"], 1)

    def test_wifi_networks_get_settings_like_fields(self):
        networks = _normalize_wifi_networks(
            [
                {
                    "ssid": "Freebox-C81246",
                    "bssid": "aa:bb:cc:dd:ee:ff",
                    "channel": "11",
                    "frequency": "",
                    "signal": -58,
                    "security": "WPA2-Personnel",
                    "connected": True,
                },
                {
                    "ssid": "",
                    "bssid": "11:22:33:44:55:66",
                    "channel": "40",
                    "frequency": "",
                    "signal": -70,
                    "security": "Open",
                },
            ]
        )
        self.assertEqual(networks[0]["name"], "Freebox-C81246")
        self.assertEqual(networks[0]["status"], "connecte")
        self.assertEqual(networks[0]["band"], "2.4 GHz")
        self.assertEqual(networks[0]["privacy"], "securise")
        self.assertEqual(networks[1]["name"], "Reseau masque")
        self.assertEqual(networks[1]["privacy"], "ouvert")

    def test_bluetooth_items_get_settings_like_fields(self):
        items = _normalize_bluetooth_items(
            [{"name": "Casque", "identifier": "AA:BB:CC:DD:EE:FF", "status": "connu"}],
            live_scan=True,
        )
        self.assertEqual(items[0]["name"], "Casque")
        self.assertEqual(items[0]["identifier"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(items[0]["source"], "scan visible")

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
        self.assertIn("mobile_operator_available", result)

    def test_mobile_operator_requires_the_local_termux_api(self):
        with patch("cybertoolbox.labs.wireless.shutil.which", return_value=None):
            result = mobile_operator_info()
        self.assertFalse(result["available"])
        self.assertEqual(result["scope"], "appareil courant uniquement")
        self.assertEqual(result["operator"], {})

    def test_mobile_operator_filters_sensitive_identifiers(self):
        payload = (
            '{"network_operator_name":"Orange F",'
            '"network_operator":"20801","network_type":"LTE",'
            '"sim_operator_name":"Orange","device_id":"private-imei",'
            '"sim_serial_number":"private-iccid",'
            '"sim_subscriber_id":"private-imsi"}'
        )
        with patch(
            "cybertoolbox.labs.wireless.shutil.which",
            return_value="/data/data/com.termux/files/usr/bin/termux-telephony-deviceinfo",
        ):
            with patch(
                "cybertoolbox.labs.wireless._run",
                return_value={"available": True, "output": payload, "error": ""},
            ):
                result = mobile_operator_info()
        self.assertTrue(result["available"])
        self.assertEqual(result["operator"]["network_operator_name"], "Orange F")
        self.assertNotIn("device_id", repr(result))
        self.assertNotIn("private-imei", repr(result))
        self.assertNotIn("private-iccid", repr(result))
        self.assertNotIn("private-imsi", repr(result))

    def test_wifi_security_lesson_flags_open_networks(self):
        self.assertTrue(any("ouvert" in item.lower() for item in wifi_security_lesson("OPEN")))

    def test_packet_observer_summarizes_demo_traffic(self):
        result = observe_packets()
        self.assertEqual(result["mode"], "log_or_demo")
        self.assertGreater(result["statistics"]["total"], 0)
        self.assertIn("TCP", result["statistics"]["protocols"])
        self.assertIn("UDP", result["statistics"]["protocols"])
        summaries = " ".join(packet["summary"] for packet in result["packets"])
        self.assertIn("TCP SYN", summaries)
        self.assertIn("requete DNS", summaries)
        self.assertTrue(any("HTTPS" in item for item in result["limitations"]))

    def test_public_exposure_lists_visible_directory_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "public.txt").write_text("demo", encoding="utf-8")
            (root / "notes").mkdir()
            result = inspect_public_exposure(str(root))
        self.assertEqual(result["mode"], "public_exposure")
        self.assertEqual(result["kind"], "path")
        self.assertTrue(result["directory_listing"])
        names = {item["name"] for item in result["resources"]}
        self.assertEqual(names, {"notes", "public.txt"})
        self.assertTrue(any("brute force" in item.lower() for item in result["limitations"]))

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

    def test_guided_mission_templates_can_be_saved(self):
        self.assertGreaterEqual(len(mission_templates()), 5)
        with tempfile.TemporaryDirectory() as directory:
            from cybertoolbox import mission

            previous = mission.MISSIONS_DIR
            mission.MISSIONS_DIR = Path(directory)
            try:
                path = create_mission_from_template("traffic-reading-lab")
                payload = path.read_text(encoding="utf-8")
            finally:
                mission.MISSIONS_DIR = previous
        self.assertIn("Lecture trafic pedagogique", payload)
        self.assertIn("Packet Observer", payload)

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
                app_color_mode="light",
                map_color_mode="night",
                glass_effect=False,
                glass_opacity=0.45,
                default_ports="22,80",
            )
            save_settings(expected, path)
            loaded = load_settings(path)
            self.assertEqual(loaded.language, "en")
            self.assertEqual(loaded.report_mode, "off")
            self.assertEqual(loaded.theme, "github")
            self.assertEqual(loaded.app_color_mode, "light")
            self.assertEqual(loaded.map_color_mode, "night")
            self.assertFalse(loaded.glass_effect)
            self.assertEqual(loaded.glass_opacity, 0.45)
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

    def test_recon_records_are_structured_json(self):
        categories = {
            "network": {
                "title": "Reseau IP",
                "engine": "test",
                "items": [{"address": "192.168.1.10", "hostname": "nas.local"}],
            },
            "ports": {
                "title": "Ports TCP",
                "engine": "test",
                "items": [
                    {"address": "192.168.1.10", "port": 445, "service": "smb"},
                    {"address": "192.168.1.10", "port": 80, "service": "http"},
                ],
            },
            "wifi": {
                "title": "Wi-Fi visible",
                "engine": "test",
                "items": [{"ssid": "Guest", "security": "open", "signal": -50}],
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            saved = save_recon_records(categories, subject="192.168.1.0/24", root=root)
            self.assertEqual(len(saved["artifacts"]), 4)
            self.assertEqual(len(saved["events"]), 4)
            self.assertGreaterEqual(len(saved["correlations"]), 3)
            self.assertEqual(records_summary(root)["artifacts"], 4)
            correlation_titles = {
                load_record(path, root)["title"]
                for path in list_records("correlation", root)
            }
            self.assertIn("NAS probable", correlation_titles)
            artifact_paths = list_records("artifact", root)
            self.assertTrue(artifact_paths[0].read_text(encoding="utf-8").strip().startswith("{"))
            self.assertGreater(delete_all_records(root=root), 0)

    def test_global_correlation_reuses_saved_artifacts_without_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            save_record(
                Artifact(
                    kind="device",
                    source="test",
                    title="192.168.1.10",
                    summary="Appareil actif detecte: 192.168.1.10",
                    value="192.168.1.10",
                    confidence="moyenne",
                    data={"address": "192.168.1.10"},
                ),
                root,
            )
            for port, service in ((445, "smb"), (80, "http")):
                save_record(
                    Artifact(
                        kind="service",
                        source="test",
                        title=f"192.168.1.10:{port}",
                        summary=f"Port ouvert detecte: {port}/tcp {service}",
                        value=str(port),
                        confidence="moyenne",
                        data={"address": "192.168.1.10", "port": port, "service": service},
                    ),
                    root,
                )
            first = generate_correlations_from_records(root)
            second = generate_correlations_from_records(root)
            self.assertGreaterEqual(first["generated"], 1)
            self.assertEqual(second["generated"], 0)
            titles = {load_record(path, root)["title"] for path in list_records("correlation", root)}
            self.assertIn("NAS probable", titles)


if __name__ == "__main__":
    unittest.main()

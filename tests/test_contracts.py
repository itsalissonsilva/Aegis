from __future__ import annotations

import shutil
import socket
import threading
import time
import unittest
from pathlib import Path

from aegis.engine import (
    assess_pq_risk,
    audit_config,
    build_delta_report,
    build_migration_roadmap,
    classify_algorithm,
    generate_inventory_from_runs,
    probe_tls_endpoint,
    scan_codebase,
    scan_dependencies,
)
from aegis.server import (
    _inventory_sarif,
    generate_inventory,
    get_delta_report,
    get_migration_roadmap,
    scan_codebase_tool,
)
from aegis.state import StateStore


ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
TMP_ROOT = ROOT / "tests" / ".tmp"


def _ensure_tmp_dir(name: str) -> Path:
    TMP_ROOT.mkdir(parents=True, exist_ok=True)
    target = TMP_ROOT / name
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    return target


class ContractTests(unittest.TestCase):
    def test_scan_codebase_contract(self) -> None:
        result = scan_codebase(str(EXAMPLES), min_severity="low")
        self.assertIn("findings", result)
        self.assertIn("coverage", result)
        self.assertGreaterEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertTrue({"file", "line", "algo", "key_size", "severity", "context_snippet", "suggested_replacement"} <= set(finding))

    def test_audit_config_contract(self) -> None:
        result = audit_config(str(EXAMPLES / "nginx.conf"), compliance=["pci_dss"])
        self.assertIn("findings", result)
        self.assertGreaterEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertTrue({"key_path", "current_value", "issue", "severity", "compliant_value", "reference"} <= set(finding))

    def test_classify_algorithm_contract(self) -> None:
        result = classify_algorithm("RSA-2048", "signature", "used for auth")
        self.assertEqual(result["status"], "approved")
        self.assertTrue({"classical_security_bits", "pq_security_bits", "status", "nist_reference", "replacement", "migration_complexity"} <= set(result))

    def test_assess_pq_risk_contract(self) -> None:
        result = assess_pq_risk(
            [
                {
                    "name": "payments-api",
                    "algorithms": ["RSA-2048", "ECDH-P256"],
                    "data_sensitivity": "critical",
                    "data_longevity_years": 15,
                }
            ]
        )
        self.assertIn("services", result)
        service = result["services"][0]
        self.assertTrue({"name", "pq_risk_score", "risk_band", "urgency", "rationale"} <= set(service))

    def test_scan_dependencies_contract(self) -> None:
        result = scan_dependencies(str(EXAMPLES / "package.json"))
        self.assertIn("packages", result)
        self.assertIn("coverage", result)
        package = next(pkg for pkg in result["packages"] if pkg["name"] == "jsonwebtoken")
        self.assertTrue({"name", "version", "crypto_usage", "known_vulns", "pq_safe", "upgrade_path"} <= set(package))

    def test_scan_dependencies_yarn_lock(self) -> None:
        result = scan_dependencies(str(EXAMPLES / "package.json"), str(EXAMPLES / "yarn.lock"))
        names = {pkg["name"] for pkg in result["packages"]}
        self.assertIn("node-forge", names)
        self.assertIn("jsonwebtoken", names)

    def test_scan_dependencies_pnpm_lock(self) -> None:
        result = scan_dependencies(str(EXAMPLES / "package.json"), str(EXAMPLES / "pnpm-lock.yaml"))
        names = {pkg["name"] for pkg in result["packages"]}
        self.assertIn("libsodium-wrappers", names)
        self.assertIn("jsonwebtoken", names)

    def test_scan_dependencies_cargo_contract(self) -> None:
        result = scan_dependencies(str(EXAMPLES / "Cargo.toml"))
        self.assertEqual(result["coverage"]["ecosystem"], "cargo")
        package = next(pkg for pkg in result["packages"] if pkg["name"] == "openssl")
        self.assertEqual(package["version"], "0.10.54")
        self.assertGreaterEqual(len(package["known_vulns"]), 1)

    def test_scan_dependencies_pyproject_poetry_contract(self) -> None:
        result = scan_dependencies(str(EXAMPLES / "pyproject.toml"))
        self.assertEqual(result["coverage"]["ecosystem"], "pypi")
        names = {pkg["name"] for pkg in result["packages"]}
        self.assertIn("pycrypto", names)
        self.assertIn("cryptography", names)
        pycrypto = next(pkg for pkg in result["packages"] if pkg["name"] == "pycrypto")
        self.assertGreaterEqual(len(pycrypto["known_vulns"]), 1)

    def test_scan_dependencies_maven_contract(self) -> None:
        result = scan_dependencies(str(EXAMPLES / "pom.xml"))
        self.assertEqual(result["coverage"]["ecosystem"], "maven")
        names = {pkg["name"] for pkg in result["packages"]}
        self.assertIn("org.bouncycastle:bcprov-jdk18on", names)
        self.assertIn("org.bouncycastle:bcpkix-jdk18on", names)

    def test_probe_tls_failure_contract(self) -> None:
        result = probe_tls_endpoint("127.0.0.1", 1)
        required = {
            "tls_version",
            "negotiated_cipher",
            "supported_ciphers",
            "cert_chain",
            "key_algo",
            "key_bits",
            "sig_algo",
            "expiry",
            "ocsp_status",
            "pq_hybrid_detected",
            "findings",
        }
        self.assertTrue(required <= set(result))
        self.assertIsInstance(result["findings"], list)

    def test_probe_tls_smtp_starttls_path(self) -> None:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        seen: list[str] = []

        def run_server() -> None:
            conn, _ = server.accept()
            conn.sendall(b"220 fake-smtp\r\n")
            seen.append(conn.recv(4096).decode("utf-8", errors="ignore"))
            conn.sendall(b"250-localhost\r\n250-STARTTLS\r\n250 OK\r\n")
            seen.append(conn.recv(4096).decode("utf-8", errors="ignore"))
            conn.sendall(b"220 Ready to start TLS\r\n")
            time.sleep(0.2)
            conn.close()
            server.close()

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        result = probe_tls_endpoint("127.0.0.1", port, starttls="smtp")
        thread.join(timeout=2)
        self.assertTrue(seen[0].startswith("EHLO"))
        self.assertTrue(seen[1].startswith("STARTTLS"))
        self.assertIn("findings", result)

    def test_probe_tls_imap_starttls_path(self) -> None:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        seen: list[str] = []

        def run_server() -> None:
            conn, _ = server.accept()
            conn.sendall(b"* OK fake-imap\r\n")
            seen.append(conn.recv(4096).decode("utf-8", errors="ignore"))
            conn.sendall(b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\na001 OK CAPABILITY completed\r\n")
            seen.append(conn.recv(4096).decode("utf-8", errors="ignore"))
            conn.sendall(b"a002 OK Begin TLS negotiation now\r\n")
            time.sleep(0.2)
            conn.close()
            server.close()

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        result = probe_tls_endpoint("127.0.0.1", port, starttls="imap")
        thread.join(timeout=2)
        self.assertTrue(seen[0].startswith("a001 CAPABILITY"))
        self.assertTrue(seen[1].startswith("a002 STARTTLS"))
        self.assertIn("findings", result)

    def test_probe_tls_ftp_starttls_path(self) -> None:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        seen: list[str] = []

        def run_server() -> None:
            conn, _ = server.accept()
            conn.sendall(b"220 fake-ftp\r\n")
            seen.append(conn.recv(4096).decode("utf-8", errors="ignore"))
            conn.sendall(b"234 Proceed with negotiation.\r\n")
            time.sleep(0.2)
            conn.close()
            server.close()

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        result = probe_tls_endpoint("127.0.0.1", port, starttls="ftp")
        thread.join(timeout=2)
        self.assertTrue(seen[0].startswith("AUTH TLS"))
        self.assertIn("findings", result)

    def test_probe_tls_postgres_upgrade_path(self) -> None:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        seen: list[bytes] = []

        def run_server() -> None:
            conn, _ = server.accept()
            seen.append(conn.recv(8))
            conn.sendall(b"S")
            time.sleep(0.2)
            conn.close()
            server.close()

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        result = probe_tls_endpoint("127.0.0.1", port, starttls="postgres")
        thread.join(timeout=2)
        self.assertEqual(seen[0], b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
        self.assertIn("findings", result)

    def test_probe_tls_mysql_upgrade_path(self) -> None:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        seen: list[bytes] = []

        def run_server() -> None:
            conn, _ = server.accept()
            payload = bytearray()
            payload.append(10)
            payload.extend(b"8.0.36\x00")
            payload.extend((1).to_bytes(4, "little"))
            payload.extend(b"abcdefgh")
            payload.extend(b"\x00")
            payload.extend((0xFFFF & 0x0800).to_bytes(2, "little"))
            payload.extend(b"\x21")
            payload.extend(b"\x00\x00")
            payload.extend((0).to_bytes(2, "little"))
            payload.extend(b"\x15")
            payload.extend(b"\x00" * 10)
            payload.extend(b"ijklmnopqrstuv")
            payload.extend(b"\x00")
            payload.extend(b"mysql_native_password\x00")
            header = len(payload).to_bytes(3, "little") + b"\x00"
            conn.sendall(header + payload)
            seen.append(conn.recv(4096))
            time.sleep(0.2)
            conn.close()
            server.close()

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        result = probe_tls_endpoint("127.0.0.1", port, starttls="mysql")
        thread.join(timeout=2)
        self.assertGreaterEqual(len(seen[0]), 36)
        self.assertEqual(seen[0][3], 1)
        client_flags = int.from_bytes(seen[0][4:8], "little")
        self.assertTrue(client_flags & 0x0800)
        self.assertIn("findings", result)

    def test_probe_tls_ldap_starttls_path(self) -> None:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        seen: list[bytes] = []

        def run_server() -> None:
            conn, _ = server.accept()
            seen.append(conn.recv(4096))
            conn.sendall(bytes.fromhex("300c02010178070a010004000400"))
            time.sleep(0.2)
            conn.close()
            server.close()

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        result = probe_tls_endpoint("127.0.0.1", port, starttls="ldap")
        thread.join(timeout=2)
        self.assertTrue(seen[0].startswith(bytes.fromhex("301d02010177")))
        self.assertIn("findings", result)

    def test_probe_tls_pop3_starttls_path(self) -> None:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        seen: list[str] = []

        def run_server() -> None:
            conn, _ = server.accept()
            conn.sendall(b"+OK fake-pop3\r\n")
            seen.append(conn.recv(4096).decode("utf-8", errors="ignore"))
            conn.sendall(b"+OK Begin TLS negotiation\r\n")
            time.sleep(0.2)
            conn.close()
            server.close()

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        result = probe_tls_endpoint("127.0.0.1", port, starttls="pop3")
        thread.join(timeout=2)
        self.assertTrue(seen[0].startswith("STLS"))
        self.assertIn("findings", result)

    def test_probe_tls_xmpp_starttls_path(self) -> None:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        seen: list[str] = []

        def run_server() -> None:
            conn, _ = server.accept()
            seen.append(conn.recv(4096).decode("utf-8", errors="ignore"))
            conn.sendall(
                b"<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='localhost' id='1' version='1.0'><stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>"
            )
            seen.append(conn.recv(4096).decode("utf-8", errors="ignore"))
            conn.sendall(b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
            time.sleep(0.2)
            conn.close()
            server.close()

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        result = probe_tls_endpoint("127.0.0.1", port, starttls="xmpp")
        thread.join(timeout=2)
        self.assertIn("<stream:stream", seen[0])
        self.assertIn("<starttls", seen[1].lower())
        self.assertIn("findings", result)

    def test_inventory_and_roadmap_contracts(self) -> None:
        state_root = _ensure_tmp_dir("inventory_contracts")
        store = StateStore(state_root)
        scan = scan_codebase(str(EXAMPLES), min_severity="low")
        audit = audit_config(str(EXAMPLES / "nginx.conf"))
        sid1 = store.save_run("scan_codebase", {}, scan)
        sid2 = store.save_run("audit_config", {}, audit)
        inventory_result = generate_inventory_from_runs([store.get_run(sid1), store.get_run(sid2)], group_by="severity")
        inventory = inventory_result["inventory"]
        self.assertTrue({"summary_stats", "grouped_findings", "coverage_metadata", "scan_timestamps"} <= set(inventory))
        roadmap = build_migration_roadmap(inventory)
        self.assertIn("phases", roadmap)
        self.assertGreaterEqual(len(roadmap["phases"]), 1)
        phase = roadmap["phases"][0]
        self.assertTrue({"priority", "findings_addressed", "effort_weeks", "patch_examples", "compliance_unlocked", "pq_risk_reduction_delta"} <= set(phase))

    def test_delta_report_contract(self) -> None:
        baseline = {
            "summary_stats": {"total_findings": 1, "critical": 1, "high": 0, "medium": 0, "low": 0},
            "grouped_findings": {"critical": [{"file": "a.py", "line": 1, "algo": "MD5", "severity": "critical"}]},
            "coverage_metadata": {"source_runs": 1},
            "scan_timestamps": ["2026-01-01T00:00:00+00:00"],
        }
        current = {
            "summary_stats": {"total_findings": 1, "critical": 0, "high": 1, "medium": 0, "low": 0},
            "grouped_findings": {"high": [{"file": "a.py", "line": 2, "algo": "SHA-1", "severity": "high"}]},
            "coverage_metadata": {"source_runs": 1},
            "scan_timestamps": ["2026-01-02T00:00:00+00:00"],
        }
        result = build_delta_report(baseline, current)
        self.assertTrue({"resolved", "regressed", "new_findings", "pq_score_delta", "compliance_delta", "summary_narrative"} <= set(result))

    def test_sarif_level_normalization(self) -> None:
        sarif = _inventory_sarif(
            {
                "summary_stats": {"total_findings": 1, "critical": 1, "high": 0, "medium": 0, "low": 0},
                "grouped_findings": {"critical": [{"file": "a.py", "line": 1, "algo": "MD5", "severity": "critical", "suggested_replacement": "Use SHA-256."}]},
                "coverage_metadata": {"source_runs": 1},
                "scan_timestamps": [],
            }
        )
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "error")


class ServerFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state_root = _ensure_tmp_dir("server_flow")

    def test_server_inventory_round_trip(self) -> None:
        from aegis import server as server_module

        original_state = server_module.STATE
        server_module.STATE = StateStore(self.state_root)
        try:
            scan = scan_codebase_tool(str(EXAMPLES), min_severityopt="low")
            inventory = generate_inventory([scan["scan_id"]], group_byopt="severity", formatopt="json")
            roadmap = get_migration_roadmap(inventory["inventory_id"])
            delta = get_delta_report(inventory["inventory_id"], inventory["inventory_id"])
        finally:
            server_module.STATE = original_state

        self.assertIn("inventory_id", inventory)
        self.assertIn("inventory", inventory)
        self.assertIn("phases", roadmap)
        self.assertIn("summary_narrative", delta)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import ast
import fnmatch
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

from .knowledge import ALGORITHM_PROFILES, LANGUAGE_EXTENSIONS, SEVERITY_ORDER


CRYPTO_PATTERNS: list[dict[str, Any]] = [
    {"pattern": r"\bmd5\b", "algo": "MD5", "severity": "critical", "replacement_key": "md5"},
    {"pattern": r"\bsha1\b|\bsha-1\b", "algo": "SHA-1", "severity": "high", "replacement_key": "sha1"},
    {"pattern": r"\bdes\b", "algo": "DES", "severity": "critical", "replacement_key": "des"},
    {"pattern": r"\b3des\b|\btripledes\b", "algo": "3DES", "severity": "high", "replacement_key": "3des"},
    {"pattern": r"\baes[-_]?128[-_]?cbc\b", "algo": "AES-128-CBC", "severity": "medium", "replacement_key": "aes-128-cbc"},
    {"pattern": r"\baes[-_]?256[-_]?cbc\b", "algo": "AES-256-CBC", "severity": "low", "replacement_key": "aes-256-cbc"},
    {"pattern": r"\baes[-_]?128[-_]?gcm\b", "algo": "AES-128-GCM", "severity": "low", "replacement_key": "aes-128-gcm"},
    {"pattern": r"\baes[-_]?256[-_]?gcm\b", "algo": "AES-256-GCM", "severity": "low", "replacement_key": "aes-256-gcm"},
    {"pattern": r"\bchacha20[-_]?poly1305\b", "algo": "ChaCha20-Poly1305", "severity": "low", "replacement_key": "chacha20-poly1305"},
    {"pattern": r"\brsa[^\n]{0,20}\b1024\b|\brsa[-_]?1024\b", "algo": "RSA-1024", "severity": "critical", "replacement_key": "rsa-1024"},
    {"pattern": r"\brsa[^\n]{0,20}\b2048\b|\brsa[-_]?2048\b", "algo": "RSA-2048", "severity": "medium", "replacement_key": "rsa-2048"},
    {"pattern": r"\brsa[^\n]{0,20}\b3072\b|\brsa[-_]?3072\b", "algo": "RSA-3072", "severity": "low", "replacement_key": "rsa-3072"},
    {"pattern": r"\becdh[-_]?p256\b|\bsecp256r1\b", "algo": "ECDH-P256", "severity": "medium", "replacement_key": "ecdh-p256"},
    {"pattern": r"\becdsa[-_]?p256\b", "algo": "ECDSA-P256", "severity": "medium", "replacement_key": "ecdsa-p256"},
    {"pattern": r"\bx25519\b", "algo": "X25519", "severity": "medium", "replacement_key": "x25519"},
    {"pattern": r"\bhmac[-_]?sha256\b", "algo": "HMAC-SHA256", "severity": "low", "replacement_key": "hmac-sha256"},
    {"pattern": r"\bpbkdf2\b", "algo": "PBKDF2", "severity": "medium", "replacement_key": "pbkdf2"},
    {"pattern": r"\bargon2(id)?\b", "algo": "Argon2id", "severity": "low", "replacement_key": "argon2"},
    {"pattern": r"\bml-kem[-_]?768\b", "algo": "ML-KEM-768", "severity": "low", "replacement_key": "ml-kem-768"},
    {"pattern": r"\bml-dsa[-_]?65\b", "algo": "ML-DSA-65", "severity": "low", "replacement_key": "ml-dsa-65"},
    {"pattern": r"['\"]hs256['\"]", "algo": "JWT-HS256", "severity": "medium", "replacement_key": "hmac-sha256"},
    {"pattern": r"['\"]rs256['\"]", "algo": "JWT-RS256", "severity": "medium", "replacement_key": "rsa-2048"},
    {"pattern": r"['\"]rs384['\"]|['\"]rs512['\"]", "algo": "JWT-RS*", "severity": "low", "replacement_key": "rsa-3072"},
    {"pattern": r"['\"]es256['\"]|['\"]es384['\"]|['\"]es512['\"]", "algo": "JWT-ES*", "severity": "medium", "replacement_key": "ecdsa-p256"},
    {"pattern": r"['\"]eddsa['\"]", "algo": "JWT-EdDSA", "severity": "low", "replacement_key": "ml-dsa-65"},
    {"pattern": r"['\"]none['\"]", "algo": "JWT-none", "severity": "critical", "replacement_key": "hmac-sha256"},
    {"pattern": r"\b(512|1024)\s*bit\b", "algo": "Weak Key Size Guidance", "severity": "critical", "replacement_key": "rsa-2048"},
]

TEST_FILE_PATTERNS = ("test_*", "*_test.*", "tests/*", "*/tests/*")
TLS_ENUMERATION_CIPHERS = [
    "ECDHE+AESGCM",
    "ECDHE+CHACHA20",
    "DHE+AESGCM",
    "AESGCM",
    "HIGH:!aNULL:!eNULL:!MD5",
    "HIGH:!aNULL:!eNULL",
]
DEPENDENCY_HEURISTICS: list[dict[str, Any]] = [
    {"match": "cryptography", "usage": ["x509", "tls", "hashing", "signatures"], "pq_safe": False, "upgrade": "Track PQ support and avoid SHA-1/legacy RSA defaults."},
    {"match": "pyopenssl", "usage": ["tls", "x509"], "pq_safe": False, "upgrade": "Prefer maintained OpenSSL bindings and modern TLS settings."},
    {"match": "openssl", "usage": ["tls", "x509", "symmetric crypto"], "pq_safe": False, "upgrade": "Use OpenSSL 3.x with modern providers and TLS 1.3 defaults."},
    {"match": "bcrypt", "usage": ["password hashing"], "pq_safe": True, "upgrade": "Argon2id may offer a stronger modern baseline."},
    {"match": "argon2", "usage": ["password hashing"], "pq_safe": True, "upgrade": "No immediate migration required."},
    {"match": "jsonwebtoken", "usage": ["jwt signing"], "pq_safe": False, "upgrade": "Prefer PS256/ES384/EdDSA and verify alg allowlists."},
    {"match": "jose", "usage": ["jwe", "jws", "jwt"], "pq_safe": False, "upgrade": "Plan for PQ-capable signature and KEM support."},
    {"match": "nacl", "usage": ["public-key crypto", "box", "signatures"], "pq_safe": False, "upgrade": "Monitor libsodium PQ roadmap for hybrid transitions."},
    {"match": "libsodium", "usage": ["public-key crypto", "secretbox", "signatures"], "pq_safe": False, "upgrade": "Monitor PQ and hybrid support in upstream releases."},
    {"match": "ring", "usage": ["hashing", "signature verification", "aead"], "pq_safe": False, "upgrade": "Review for non-PQ primitives in long-lived contexts."},
    {"match": "rustls", "usage": ["tls"], "pq_safe": False, "upgrade": "Adopt hybrid groups once supported in your deployment path."},
    {"match": "boring", "usage": ["tls"], "pq_safe": False, "upgrade": "Track hybrid KEM support and modern cipher defaults."},
    {"match": "bcprov", "usage": ["jce provider", "pkix", "cms"], "pq_safe": True, "upgrade": "Use current provider releases with PQ algorithms where possible."},
    {"match": "bcpkix", "usage": ["pkix", "cms"], "pq_safe": True, "upgrade": "Use current provider releases with PQ algorithms where possible."},
]
KNOWN_VULN_HINTS: list[dict[str, Any]] = [
    {"match": "pycrypto", "issue": "Unmaintained cryptographic library.", "severity": "high", "reference": "Project archived; migrate to pyca/cryptography or PyCryptodome."},
    {"match": "node-forge", "issue": "Review carefully for legacy RSA/PKCS#1 and TLS usage.", "severity": "medium", "reference": "Use modern JOSE/TLS libraries where possible."},
    {"match": "jsonwebtoken", "issue": "JWT libraries require strict alg and key validation to avoid misuse.", "severity": "medium", "reference": "Audit allowlists, issuer/audience checks, and key rotation."},
]

_ADVISORY_CACHE: dict[str, Any] | None = None
DOC_EXTENSIONS = {".md", ".txt", ".rst", ".adoc"}


def normalize_algorithm_name(value: str) -> str:
    normalized = value.strip().lower().replace(" ", "-").replace("_", "-")
    if normalized == "sha-1":
        return "sha1"
    return normalized


def classify_algorithm(algorithm: str, use_case: str, context: str | None = None) -> dict[str, Any]:
    normalized = normalize_algorithm_name(algorithm)
    profile = ALGORITHM_PROFILES.get(normalized)
    if profile is None:
        guessed_status = "approved" if any(token in normalized for token in ("aes-256", "sha-256", "sha-384", "sha3", "ml-kem", "ml-dsa")) else "deprecated"
        return {
            "classical_security_bits": None,
            "pq_security_bits": 0,
            "status": guessed_status,
            "nist_reference": "Manual review required",
            "replacement": "Review manually against current NIST guidance.",
            "migration_complexity": "moderate",
            "context": context,
            "use_case": use_case,
        }
    return {
        "classical_security_bits": profile.classical_security_bits,
        "pq_security_bits": profile.pq_security_bits,
        "status": profile.status,
        "nist_reference": profile.nist_reference,
        "replacement": profile.replacement,
        "migration_complexity": profile.migration_complexity,
        "context": context,
        "canonical_name": profile.canonical_name,
        "use_case": use_case or profile.use_case,
    }


def severity_at_least(candidate: str, minimum: str) -> bool:
    return SEVERITY_ORDER[candidate] >= SEVERITY_ORDER[minimum]


def detect_language(path: Path) -> str | None:
    if path.suffix.lower() in DOC_EXTENSIONS:
        return "docs"
    return LANGUAGE_EXTENSIONS.get(path.suffix.lower())


def is_test_file(path: Path) -> bool:
    normalized = path.as_posix()
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in TEST_FILE_PATTERNS)


def extract_key_size(line: str, algo: str) -> int | None:
    match = re.search(r"\b(64|80|96|112|128|192|224|256|512|1024|2048|3072|4096)\b", line)
    if match:
        return int(match.group(1))
    if "RSA-1024" in algo:
        return 1024
    if "RSA-2048" in algo:
        return 2048
    if "RSA-3072" in algo:
        return 3072
    if "P256" in algo:
        return 256
    return None


def _call_name(func: ast.AST) -> str | None:
    parts: list[str] = []
    current = func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _ast_findings_for_python(file_path: Path, content: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return findings

    interesting = {
        "hashlib.md5": "MD5",
        "hashlib.sha1": "SHA-1",
        "hashes.MD5": "MD5",
        "hashes.SHA1": "SHA-1",
    }

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> Any:
            name = _call_name(node.func)
            if name in interesting:
                algo = interesting[name]
                profile = ALGORITHM_PROFILES[normalize_algorithm_name(algo)]
                findings.append(
                    {
                        "file": str(file_path),
                        "line": node.lineno,
                        "algo": algo,
                        "key_size": extract_key_size(ast.get_source_segment(content, node) or "", algo),
                        "severity": profile.severity,
                        "context_snippet": (ast.get_source_segment(content, node) or "").strip(),
                        "suggested_replacement": profile.suggested_replacement,
                    }
                )
            self.generic_visit(node)

    Visitor().visit(tree)
    return findings


def scan_codebase(path: str, languages: list[str] | None = None, depth: int | None = None, include_tests: bool = False, min_severity: str = "medium") -> dict[str, Any]:
    root = Path(path).expanduser().resolve()
    allowed_languages = set(languages or [])
    findings: list[dict[str, Any]] = []
    files_scanned = 0

    if root.is_file():
        candidates = [root]
    else:
        candidates = []
        root_depth = len(root.parts)
        for current_root, dirnames, filenames in os.walk(root):
            current_path = Path(current_root)
            if depth is not None and (len(current_path.parts) - root_depth) >= depth:
                dirnames[:] = []
            for filename in filenames:
                candidates.append(current_path / filename)

    for file_path in candidates:
        language = detect_language(file_path)
        if language is None:
            continue
        if allowed_languages and language not in allowed_languages:
            continue
        if not include_tests and is_test_file(file_path):
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        files_scanned += 1
        if language == "python":
            findings.extend([f for f in _ast_findings_for_python(file_path, content) if severity_at_least(f["severity"], min_severity)])
        for line_number, line in enumerate(content.splitlines(), start=1):
            lowered = line.lower()
            for pattern_entry in CRYPTO_PATTERNS:
                if not severity_at_least(pattern_entry["severity"], min_severity):
                    continue
                if re.search(pattern_entry["pattern"], lowered):
                    profile = ALGORITHM_PROFILES[pattern_entry["replacement_key"]]
                    findings.append(
                        {
                            "file": str(file_path),
                            "line": line_number,
                            "algo": pattern_entry["algo"],
                            "key_size": extract_key_size(line, pattern_entry["algo"]),
                            "severity": pattern_entry["severity"],
                            "context_snippet": line.strip()[:240],
                            "suggested_replacement": profile.suggested_replacement,
                        }
                    )

    findings = _dedupe_findings(findings)
    findings.sort(key=lambda item: (-SEVERITY_ORDER[item["severity"]], item["file"], item["line"]))
    return {
        "findings": findings,
        "coverage": {
            "path": str(root),
            "files_scanned": files_scanned,
            "languages": sorted(allowed_languages) if allowed_languages else "auto-detect",
            "include_tests": include_tests,
            "depth": depth,
        },
    }


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    deduped = []
    for finding in findings:
        key = (finding.get("file"), finding.get("line"), finding.get("algo"), finding.get("severity"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def audit_config(path: str, format_hint: str = "auto", compliance: list[str] | None = None) -> dict[str, Any]:
    target = Path(path).expanduser().resolve()
    findings: list[dict[str, Any]] = []
    files = [target] if target.is_file() else [p for p in target.rglob("*") if p.is_file()]
    compliance = compliance or []

    for file_path in files:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        inferred = _infer_config_format(file_path, format_hint, content)
        findings.extend(_audit_single_config(file_path, content, inferred, compliance))

    findings.sort(key=lambda item: (-SEVERITY_ORDER[item["severity"]], item["key_path"]))
    return {"findings": findings, "coverage": {"path": str(target), "format": format_hint, "frameworks": compliance}}


def _infer_config_format(file_path: Path, format_hint: str, content: str) -> str:
    if format_hint != "auto":
        return format_hint
    name = file_path.name.lower()
    lowered = content.lower()
    if "sshd" in name or "ssh" in name:
        return "ssh"
    if "nginx" in name or "ssl_ciphers" in lowered:
        return "nginx"
    if name.endswith(".cnf") or "openssl_conf" in lowered:
        return "openssl"
    if "jwt" in name or '"alg"' in lowered:
        return "jwt"
    if "secret" in name or "kind: secret" in lowered:
        return "k8s_secret"
    return "auto"


def _audit_single_config(file_path: Path, content: str, config_format: str, compliance: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        normalized = line.strip()
        lowered = normalized.lower()
        if not normalized or normalized.startswith("#"):
            continue
        if config_format in {"ssh", "auto"} and lowered.startswith("hostkeyalgorithms") and "+ssh-rsa" in lowered:
            findings.append(_config_finding(file_path, "HostKeyAlgorithms", normalized, "SSH RSA host keys may not meet current policy.", "medium", "Use rsa-sha2-512, ecdsa-sha2-nistp384, or Ed25519 where allowed.", "NIST SP 800-131A Rev. 2", line_number))
        if config_format in {"ssh", "auto"} and lowered.startswith("ciphers") and any(token in lowered for token in ("3des", "aes128-cbc")):
            findings.append(_config_finding(file_path, "Ciphers", normalized, "Legacy SSH ciphers enabled.", "high", "Use aes256-gcm@openssh.com or chacha20-poly1305@openssh.com.", "NIST SP 800-131A Rev. 2", line_number))
        if config_format in {"nginx", "auto"} and "ssl_protocols" in lowered and ("tlsv1;" in lowered or "tlsv1.1" in lowered):
            findings.append(_config_finding(file_path, "ssl_protocols", normalized, "Deprecated TLS protocol enabled.", "high", "Allow only TLSv1.2 and TLSv1.3.", "PCI DSS / NIST guidance", line_number))
        if config_format in {"nginx", "auto"} and "ssl_ciphers" in lowered and any(token in lowered for token in ("3des", "md5", "sha1", "des")):
            findings.append(_config_finding(file_path, "ssl_ciphers", normalized, "Weak TLS ciphers configured.", "critical", "Use AEAD suites with ECDHE and AES-GCM or ChaCha20-Poly1305.", "NIST SP 800-52 Rev. 2", line_number))
        if config_format in {"openssl", "auto"} and lowered.startswith("minprotocol") and "tlsv1.0" in lowered:
            findings.append(_config_finding(file_path, "MinProtocol", normalized, "OpenSSL minimum protocol is too old.", "high", "Set MinProtocol = TLSv1.2 or TLSv1.3.", "NIST SP 800-52 Rev. 2", line_number))
        if config_format in {"jwt", "auto"} and (
            any(token in lowered for token in ('"alg"', "'alg'", "algorithm"))
            and any(token in lowered for token in ('"hs256"', "'hs256'", '"rs256"', "'rs256'", '"rs384"', "'rs384'", '"rs512"', "'rs512'", '"es256"', "'es256'", '"eddsa"', "'eddsa'", '"none"', "'none'"))
        ):
            if '"none"' in lowered or "'none'" in lowered:
                severity = "critical"
                issue = "JWT alg=none is insecure."
                compliant = "Disallow alg=none and enforce an explicit allowlist."
            elif '"rs256"' in lowered or "'rs256'" in lowered:
                severity = "medium"
                issue = "JWT uses RS256; verify key size, rotation policy, and migration plan."
                compliant = "Prefer RSASSA-PSS, ES384, EdDSA, or a documented transition plan."
            elif '"hs256"' in lowered or "'hs256'" in lowered:
                severity = "medium"
                issue = "JWT uses HS256; verify symmetric key strength and key distribution controls."
                compliant = "Use a high-entropy shared secret or prefer asymmetric signing for multi-service trust."
            else:
                severity = "low"
                issue = "JWT algorithm configured; confirm policy alignment."
                compliant = "Prefer modern asymmetric algorithms with explicit allowlists."
            findings.append(_config_finding(file_path, "jwt.alg", normalized, issue, severity, compliant, "JWT best practices", line_number))
        if any(token in lowered for token in ("512bit", "512 bit", "1024bit", "1024 bit")) and any(token in lowered for token in ("rsa", "key size", "private key", "public key")):
            findings.append(_config_finding(file_path, "crypto.key_size", normalized, "Weak asymmetric key size guidance detected.", "critical", "Use RSA-2048 minimum; prefer RSA-3072+ or modern curves with a PQ migration plan.", "NIST SP 800-131A Rev. 2", line_number))
        if config_format in {"k8s_secret", "auto"} and "kind: secret" in lowered:
            findings.append(_config_finding(file_path, "kind", normalized, "Kubernetes Secret detected; verify at-rest encryption and KMS backing.", "medium", "Enable envelope encryption with strong KMS-backed keys.", "Kubernetes encryption at rest guidance", line_number))

    if "fips_140_3" in compliance and config_format == "openssl" and "fips" not in content.lower():
        findings.append(_config_finding(file_path, "openssl.fips", "not enabled", "Requested FIPS review but FIPS mode was not detected.", "medium", "Enable validated FIPS provider/module where required.", "FIPS 140-3", 1))
    return findings


def _config_finding(file_path: Path, key_path: str, current_value: str, issue: str, severity: str, compliant_value: str, reference: str, line: int) -> dict[str, Any]:
    return {
        "file": str(file_path),
        "line": line,
        "key_path": f"{file_path}:{key_path}",
        "current_value": current_value[:240],
        "issue": issue,
        "severity": severity,
        "compliant_value": compliant_value,
        "reference": reference,
    }


def probe_tls_endpoint(host: str, port: int = 443, sni: str | None = None, starttls: str = "none", enumerate_all: bool = False) -> dict[str, Any]:
    server_name = sni or host
    findings: list[dict[str, Any]] = []
    supported_ciphers: list[str] = []
    cert_chain: list[dict[str, Any]] = []
    tls_version = None
    negotiated_cipher = None
    key_algo = None
    key_bits = None
    sig_algo = None
    expiry = None
    ocsp_status = "unchecked"
    pq_hybrid_detected = False

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as raw_sock:
            prepared_sock = _prepare_starttls(raw_sock, host, starttls)
            with context.wrap_socket(prepared_sock, server_hostname=server_name) as tls_sock:
                tls_version = tls_sock.version()
                cipher_info = tls_sock.cipher()
                negotiated_cipher = cipher_info[0] if cipher_info else None
                if negotiated_cipher and any(token in negotiated_cipher.upper() for token in ("MLKEM", "KYBER", "HYBRID")):
                    pq_hybrid_detected = True
                peer_cert = tls_sock.getpeercert()
                binary_cert = tls_sock.getpeercert(binary_form=True)
                cert_chain, cert_meta = _extract_cert_chain(tls_sock, peer_cert, binary_cert)
                key_algo = cert_meta["key_algo"]
                key_bits = cert_meta["key_bits"]
                sig_algo = cert_meta["sig_algo"]
                expiry = cert_meta["expiry"]
                ocsp_status = cert_meta["ocsp_status"]
    except Exception as exc:
        return {
            "tls_version": None,
            "negotiated_cipher": None,
            "supported_ciphers": [],
            "cert_chain": [],
            "key_algo": None,
            "key_bits": None,
            "sig_algo": None,
            "expiry": None,
            "ocsp_status": "unchecked",
            "pq_hybrid_detected": False,
            "findings": [
                {
                    "severity": "high",
                    "issue": f"TLS probe failed: {exc}",
                    "suggested_replacement": "Verify reachability, firewall rules, and SNI configuration.",
                }
            ],
        }

    if enumerate_all:
        supported_ciphers = _enumerate_supported_ciphers(host, port, server_name, starttls)

    findings.extend(_tls_findings(tls_version, negotiated_cipher, key_algo, key_bits, sig_algo, expiry, ocsp_status, pq_hybrid_detected, supported_ciphers))

    return {
        "tls_version": tls_version,
        "negotiated_cipher": negotiated_cipher,
        "supported_ciphers": supported_ciphers,
        "cert_chain": cert_chain,
        "key_algo": key_algo,
        "key_bits": key_bits,
        "sig_algo": sig_algo,
        "expiry": expiry,
        "ocsp_status": ocsp_status,
        "pq_hybrid_detected": pq_hybrid_detected,
        "findings": findings,
    }


def _prepare_starttls(raw_sock: socket.socket, host: str, starttls: str) -> socket.socket:
    mode = (starttls or "none").lower()
    if mode == "none":
        return raw_sock
    if mode == "smtp":
        _smtp_starttls(raw_sock, host)
        return raw_sock
    if mode == "imap":
        _imap_starttls(raw_sock)
        return raw_sock
    if mode == "ftp":
        _ftp_starttls(raw_sock)
        return raw_sock
    if mode == "postgres":
        _postgres_tls_upgrade(raw_sock)
        return raw_sock
    if mode == "mysql":
        _mysql_tls_upgrade(raw_sock, host)
        return raw_sock
    if mode == "ldap":
        _ldap_starttls(raw_sock)
        return raw_sock
    if mode == "pop3":
        _pop3_starttls(raw_sock)
        return raw_sock
    if mode == "xmpp":
        _xmpp_starttls(raw_sock, host)
        return raw_sock
    raise ValueError(f"Unsupported STARTTLS mode: {starttls}")


def _smtp_starttls(sock: socket.socket, host: str) -> None:
    banner = _recv_until(sock)
    if not banner.startswith("220"):
        raise RuntimeError(f"Unexpected SMTP banner: {banner.strip()}")
    _send_line(sock, f"EHLO {host}")
    ehlo = _recv_multiline(sock)
    if "STARTTLS" not in ehlo.upper():
        raise RuntimeError("SMTP server did not advertise STARTTLS.")
    _send_line(sock, "STARTTLS")
    reply = _recv_until(sock)
    if not reply.startswith("220"):
        raise RuntimeError(f"SMTP STARTTLS failed: {reply.strip()}")


def _imap_starttls(sock: socket.socket) -> None:
    banner = _recv_until(sock)
    if not banner.startswith("*"):
        raise RuntimeError(f"Unexpected IMAP banner: {banner.strip()}")
    _send_line(sock, "a001 CAPABILITY")
    capability = _recv_multiline(sock, terminal_prefix="a001 ")
    if "STARTTLS" not in capability.upper():
        raise RuntimeError("IMAP server did not advertise STARTTLS.")
    _send_line(sock, "a002 STARTTLS")
    reply = _recv_multiline(sock, terminal_prefix="a002 ")
    if "OK" not in reply.upper():
        raise RuntimeError(f"IMAP STARTTLS failed: {reply.strip()}")


def _ftp_starttls(sock: socket.socket) -> None:
    banner = _recv_until(sock)
    if not banner.startswith("220"):
        raise RuntimeError(f"Unexpected FTP banner: {banner.strip()}")
    _send_line(sock, "AUTH TLS")
    reply = _recv_until(sock)
    if not reply.startswith("234"):
        raise RuntimeError(f"FTP AUTH TLS failed: {reply.strip()}")


def _postgres_tls_upgrade(sock: socket.socket) -> None:
    # PostgreSQL SSLRequest: length=8, code=80877103
    sock.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
    reply = sock.recv(1)
    if reply != b"S":
        raise RuntimeError(f"PostgreSQL server rejected TLS upgrade: {reply!r}")


def _mysql_tls_upgrade(sock: socket.socket, host: str) -> None:
    packet = _recv_mysql_packet(sock)
    if not packet:
        raise RuntimeError("MySQL server did not send an initial handshake packet.")
    protocol_version = packet[0]
    if protocol_version != 10:
        raise RuntimeError(f"Unexpected MySQL protocol version: {protocol_version}")

    offset = 1
    while offset < len(packet) and packet[offset] != 0:
        offset += 1
    offset += 1  # server version null terminator
    if offset + 4 > len(packet):
        raise RuntimeError("Incomplete MySQL handshake packet.")
    connection_id = packet[offset : offset + 4]
    offset += 4
    auth_plugin_part_1 = packet[offset : offset + 8]
    offset += 9  # auth plugin part + filler
    capability_low = int.from_bytes(packet[offset : offset + 2], "little")
    offset += 2
    if offset >= len(packet):
        raise RuntimeError("Incomplete MySQL capability flags.")
    _charset = packet[offset]
    offset += 1
    _status_flags = packet[offset : offset + 2]
    offset += 2
    capability_high = int.from_bytes(packet[offset : offset + 2], "little")
    capability_flags = capability_low | (capability_high << 16)
    client_ssl = 0x0800
    if not (capability_flags & client_ssl):
        raise RuntimeError("MySQL server does not advertise SSL capability.")

    max_packet_size = (16 * 1024 * 1024).to_bytes(4, "little")
    charset = bytes([33])
    reserved = b"\x00" * 23
    client_flags = (
        client_ssl
        | 0x0001  # CLIENT_LONG_PASSWORD
        | 0x0008  # CLIENT_CONNECT_WITH_DB
        | 0x0200  # CLIENT_PROTOCOL_41
        | 0x8000  # CLIENT_SECURE_CONNECTION
        | 0x00080000  # CLIENT_PLUGIN_AUTH
    )
    ssl_request = client_flags.to_bytes(4, "little") + max_packet_size + charset + reserved
    _send_mysql_packet(sock, ssl_request, sequence_id=1)


def _ldap_starttls(sock: socket.socket) -> None:
    # LDAP StartTLS extended request per RFC 4511 with OID 1.3.6.1.4.1.1466.20037
    request = bytes.fromhex(
        "301d02010177188016312e332e362e312e342e312e313436362e3230303337"
    )
    sock.sendall(request)
    reply = sock.recv(4096)
    if len(reply) < 14:
        raise RuntimeError("LDAP server returned an incomplete StartTLS response.")
    if b"\x0a\x01\x00" not in reply:
        raise RuntimeError(f"LDAP StartTLS failed: {reply!r}")


def _pop3_starttls(sock: socket.socket) -> None:
    banner = _recv_until(sock)
    if not banner.startswith("+OK"):
        raise RuntimeError(f"Unexpected POP3 banner: {banner.strip()}")
    _send_line(sock, "STLS")
    reply = _recv_until(sock)
    if not reply.startswith("+OK"):
        raise RuntimeError(f"POP3 STLS failed: {reply.strip()}")


def _xmpp_starttls(sock: socket.socket, host: str) -> None:
    opening = (
        f"<stream:stream to='{host}' "
        "xmlns='jabber:client' "
        "xmlns:stream='http://etherx.jabber.org/streams' "
        "version='1.0'>"
    )
    sock.sendall(opening.encode("utf-8"))
    features = _recv_until(sock, buffer_size=8192)
    if "<starttls" not in features.lower():
        raise RuntimeError("XMPP server did not advertise STARTTLS.")
    sock.sendall(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
    reply = _recv_until(sock, buffer_size=8192)
    if "<proceed" not in reply.lower():
        raise RuntimeError(f"XMPP STARTTLS failed: {reply.strip()}")


def _send_line(sock: socket.socket, line: str) -> None:
    sock.sendall(f"{line}\r\n".encode("ascii"))


def _recv_mysql_packet(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 4)
    payload_length = int.from_bytes(header[:3], "little")
    return _recv_exact(sock, payload_length)


def _send_mysql_packet(sock: socket.socket, payload: bytes, sequence_id: int) -> None:
    header = len(payload).to_bytes(3, "little") + bytes([sequence_id & 0xFF])
    sock.sendall(header + payload)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("Socket closed before enough bytes were received.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_until(sock: socket.socket, buffer_size: int = 4096) -> str:
    return sock.recv(buffer_size).decode("utf-8", errors="ignore")


def _recv_multiline(sock: socket.socket, terminal_prefix: str | None = None, buffer_size: int = 4096) -> str:
    chunks: list[str] = []
    while True:
        chunk = sock.recv(buffer_size).decode("utf-8", errors="ignore")
        if not chunk:
            break
        chunks.append(chunk)
        joined = "".join(chunks)
        lines = [line for line in joined.splitlines() if line.strip()]
        if terminal_prefix:
            if any(line.startswith(terminal_prefix) for line in lines):
                break
        elif lines and not any(re.match(r"^\d{3}-", line) for line in lines[-1:]):
            break
        if len(chunk) < buffer_size:
            break
    return "".join(chunks)


def _extract_cert_chain(tls_sock: ssl.SSLSocket, peer_cert: dict[str, Any], binary_cert: bytes | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    meta = {"key_algo": None, "key_bits": None, "sig_algo": None, "expiry": None, "ocsp_status": "unknown"}

    der_chain: list[bytes] = []
    try:
        der_chain = list(tls_sock.get_verified_chain() or [])
    except Exception:
        der_chain = []
    if not der_chain:
        try:
            der_chain = list(tls_sock.get_unverified_chain() or [])
        except Exception:
            der_chain = []
    if not der_chain and binary_cert:
        der_chain = [binary_cert]

    for index, der_cert in enumerate(der_chain):
        decoded = _decode_der_certificate(der_cert)
        if decoded is None:
            continue
        record = _certificate_record_from_decoded(decoded, der_cert, index)
        chain.append(record)
        if index == 0:
            meta["key_algo"] = record.get("key_algorithm")
            meta["key_bits"] = record.get("key_bits")
            meta["sig_algo"] = record.get("signature_algorithm")
            meta["expiry"] = record.get("not_after")
            meta["ocsp_status"] = _check_ocsp_status(der_cert, record.get("ocsp_urls", []))

    if not chain and peer_cert:
        subject = _flatten_cert_name(peer_cert.get("subject", ()))
        issuer = _flatten_cert_name(peer_cert.get("issuer", ()))
        expiry = peer_cert.get("notAfter")
        meta["expiry"] = expiry
        ocsp_urls = peer_cert.get("OCSP", [])
        meta["ocsp_status"] = "present" if ocsp_urls else "absent"
        chain.append(
            {
                "index": 0,
                "subject": subject,
                "issuer": issuer,
                "not_before": peer_cert.get("notBefore"),
                "not_after": expiry,
                "sans": [value for kind, value in peer_cert.get("subjectAltName", ()) if kind == "DNS"],
                "ocsp_urls": ocsp_urls,
                "serial_number": None,
                "signature_algorithm": None,
                "key_algorithm": None,
                "key_bits": None,
            }
        )
    return chain, meta


def _decode_der_certificate(der_cert: bytes) -> dict[str, Any] | None:
    try:
        pem = ssl.DER_cert_to_PEM_cert(der_cert)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=True, encoding="utf-8") as handle:
            handle.write(pem)
            handle.flush()
            return ssl._ssl._test_decode_cert(handle.name)
    except Exception:
        return None


def _certificate_record_from_decoded(decoded: dict[str, Any], der_cert: bytes, index: int) -> dict[str, Any]:
    subject_alt = decoded.get("subjectAltName", ())
    ocsp_urls = decoded.get("OCSP", [])
    ca_issuers = decoded.get("caIssuers", [])
    pubkey = decoded.get("subjectPublicKeyInfo", {})
    return {
        "index": index,
        "subject": _flatten_cert_name(decoded.get("subject", ())),
        "issuer": _flatten_cert_name(decoded.get("issuer", ())),
        "not_before": decoded.get("notBefore"),
        "not_after": decoded.get("notAfter"),
        "sans": [value for kind, value in subject_alt if kind == "DNS"],
        "ocsp_urls": ocsp_urls,
        "ca_issuers": ca_issuers,
        "serial_number": decoded.get("serialNumber"),
        "signature_algorithm": decoded.get("signatureAlgorithm"),
        "key_algorithm": pubkey.get("algorithm"),
        "key_bits": pubkey.get("bits"),
        "sha256_fingerprint": _fingerprint_sha256(der_cert),
    }


def _fingerprint_sha256(der_cert: bytes) -> str:
    import hashlib

    return hashlib.sha256(der_cert).hexdigest()


def _check_ocsp_status(der_cert: bytes, ocsp_urls: list[str]) -> str:
    if not ocsp_urls:
        return "absent"
    try:
        pem = ssl.DER_cert_to_PEM_cert(der_cert)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="utf-8") as handle:
            handle.write(pem)
            temp_path = handle.name
        try:
            completed = subprocess.run(
                ["certutil", "-verify", "-urlfetch", temp_path],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        finally:
            try:
                Path(temp_path).unlink(missing_ok=True)
            except OSError:
                pass
    except Exception:
        return "unknown"

    combined = f"{completed.stdout}\n{completed.stderr}".lower()
    if "ocsp" in combined and "revoked" in combined:
        return "revoked"
    if "ocsp" in combined and any(token in combined for token in ("verified", "successful", "good")):
        return "good"
    if "revocation offline" in combined or "cannot find the certificate" in combined or "timeout" in combined:
        return "unknown"
    if completed.returncode == 0:
        return "good"
    return "unknown"


def _flatten_cert_name(values: Any) -> str | None:
    items: list[str] = []
    for group in values or ():
        for key, value in group:
            items.append(f"{key}={value}")
    return ", ".join(items) if items else None


def _enumerate_supported_ciphers(host: str, port: int, server_name: str, starttls: str) -> list[str]:
    supported: set[str] = set()
    for cipher_rule in TLS_ENUMERATION_CIPHERS:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers(cipher_rule)
            with socket.create_connection((host, port), timeout=5) as raw_sock:
                prepared_sock = _prepare_starttls(raw_sock, host, starttls)
                with context.wrap_socket(prepared_sock, server_hostname=server_name) as tls_sock:
                    cipher = tls_sock.cipher()
                    if cipher:
                        supported.add(cipher[0])
        except Exception:
            continue
    return sorted(supported)


def _tls_findings(
    tls_version: str | None,
    negotiated_cipher: str | None,
    key_algo: str | None,
    key_bits: int | None,
    sig_algo: str | None,
    expiry: str | None,
    ocsp_status: str,
    pq_hybrid_detected: bool,
    supported_ciphers: list[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if tls_version in {"TLSv1", "TLSv1.1"}:
        findings.append({"severity": "critical", "issue": f"Deprecated protocol negotiated: {tls_version}.", "suggested_replacement": "Disable TLS 1.0/1.1 and require TLS 1.2 or TLS 1.3."})
    elif tls_version == "TLSv1.2":
        findings.append({"severity": "medium", "issue": "TLS 1.2 negotiated; acceptable but TLS 1.3 is preferred.", "suggested_replacement": "Enable TLS 1.3 and prioritize modern AEAD suites."})

    cipher_upper = (negotiated_cipher or "").upper()
    if any(token in cipher_upper for token in ("CBC", "3DES", "DES", "RC4")):
        findings.append({"severity": "high", "issue": f"Weak or legacy cipher negotiated: {negotiated_cipher}.", "suggested_replacement": "Prefer AES-GCM or ChaCha20-Poly1305 suites with forward secrecy."})
    elif negotiated_cipher:
        findings.append({"severity": "low", "issue": f"Negotiated cipher: {negotiated_cipher}.", "suggested_replacement": "No immediate cipher change required if policy allows."})

    if key_algo and "rsa" in key_algo.lower() and key_bits and key_bits < 2048:
        findings.append({"severity": "critical", "issue": f"Certificate public key is too small: {key_algo} {key_bits}.", "suggested_replacement": "Use RSA-2048 minimum, prefer RSA-3072 or ECDSA/EdDSA with a PQ migration plan."})
    elif key_algo and "rsa" in key_algo.lower() and key_bits == 2048:
        findings.append({"severity": "medium", "issue": "Certificate uses RSA-2048; acceptable today but not PQ-safe.", "suggested_replacement": "Plan migration toward stronger or hybrid/PQ-capable certificate strategies."})

    if sig_algo and "sha1" in sig_algo.lower():
        findings.append({"severity": "high", "issue": f"Certificate uses legacy signature algorithm: {sig_algo}.", "suggested_replacement": "Use SHA-256+ based signatures."})

    if ocsp_status == "revoked":
        findings.append({"severity": "critical", "issue": "Certificate revocation check indicates the certificate is revoked.", "suggested_replacement": "Replace the certificate immediately and investigate key compromise."})
    elif ocsp_status == "absent":
        findings.append({"severity": "medium", "issue": "Certificate does not advertise an OCSP responder.", "suggested_replacement": "Publish OCSP information or ensure an alternate revocation mechanism is operational."})
    elif ocsp_status == "unknown":
        findings.append({"severity": "low", "issue": "OCSP status could not be conclusively validated.", "suggested_replacement": "Verify responder reachability and revocation checking behavior from a network-enabled environment."})

    if expiry:
        try:
            expiry_dt = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
            remaining_days = (expiry_dt - datetime.now(UTC)).days
            if remaining_days < 0:
                findings.append({"severity": "critical", "issue": "Certificate has expired.", "suggested_replacement": "Renew the certificate immediately."})
            elif remaining_days <= 30:
                findings.append({"severity": "high", "issue": f"Certificate expires soon ({remaining_days} days).", "suggested_replacement": "Renew before expiry to avoid service disruption."})
        except ValueError:
            pass

    if supported_ciphers and any(any(token in cipher.upper() for token in ("3DES", "DES", "RC4", "CBC")) for cipher in supported_ciphers):
        findings.append({"severity": "high", "issue": "Server appears to support legacy ciphers in addition to the negotiated suite.", "suggested_replacement": "Tighten the server cipher list to AEAD-only suites."})

    if not pq_hybrid_detected:
        findings.append({"severity": "medium", "issue": "No PQ-hybrid TLS signal detected.", "suggested_replacement": "Assess hybrid KEM support for long-lived confidentiality requirements."})

    return findings


def scan_dependencies(manifest_path: str, lockfile_path: str | None = None, transitive: bool = True) -> dict[str, Any]:
    manifest = Path(manifest_path).expanduser().resolve()
    lockfile = Path(lockfile_path).expanduser().resolve() if lockfile_path else _infer_lockfile_path(manifest)
    ecosystem = _detect_manifest_type(manifest)
    packages = _parse_manifest_packages(manifest, ecosystem)
    if transitive and lockfile and lockfile.exists():
        packages.extend(_parse_lockfile_packages(lockfile, ecosystem))

    unique_packages: dict[str, dict[str, Any]] = {}
    for package in packages:
        key = package["name"].lower()
        existing = unique_packages.get(key)
        if existing is None:
            unique_packages[key] = package
            continue
        existing_version = existing.get("version")
        new_version = package.get("version")
        if existing.get("scope") != "transitive" and package.get("scope") == "transitive":
            merged = dict(existing)
            merged.update(package)
            if not new_version and existing_version:
                merged["version"] = existing_version
            unique_packages[key] = merged
        elif not existing_version and new_version:
            existing["version"] = new_version

    enriched = [_enrich_package(package, ecosystem) for package in unique_packages.values()]
    enriched.sort(key=lambda item: item["name"].lower())
    return {
        "packages": enriched,
        "coverage": {
            "manifest_path": str(manifest),
            "lockfile_path": str(lockfile) if lockfile and lockfile.exists() else None,
            "ecosystem": ecosystem,
            "transitive": transitive,
        },
    }


def _infer_lockfile_path(manifest: Path) -> Path | None:
    candidates = {
        "package.json": ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"],
        "requirements.txt": ["poetry.lock", "requirements.lock", "requirements-dev.txt", "Pipfile.lock"],
        "pyproject.toml": ["poetry.lock", "Pipfile.lock"],
        "pipfile": ["Pipfile.lock"],
        "cargo.toml": ["Cargo.lock"],
        "pom.xml": [],
    }.get(manifest.name.lower(), [])
    for candidate in candidates:
        path = manifest.with_name(candidate)
        if path.exists():
            return path
    return None


def _detect_manifest_type(manifest: Path) -> str:
    name = manifest.name.lower()
    if name == "package.json":
        return "npm"
    if name in {"requirements.txt", "pyproject.toml", "poetry.lock", "pipfile", "pipfile.lock"}:
        return "pypi"
    if name == "cargo.toml":
        return "cargo"
    if name == "pom.xml":
        return "maven"
    return "unknown"


def _parse_manifest_packages(manifest: Path, ecosystem: str) -> list[dict[str, Any]]:
    if ecosystem == "npm":
        return _parse_package_json(manifest)
    if ecosystem == "pypi":
        return _parse_python_manifest(manifest)
    if ecosystem == "cargo":
        return _parse_cargo_toml(manifest)
    if ecosystem == "maven":
        return _parse_pom_xml(manifest)
    return []


def _parse_lockfile_packages(lockfile: Path, ecosystem: str) -> list[dict[str, Any]]:
    if ecosystem == "npm":
        return _parse_package_lock(lockfile)
    if ecosystem == "cargo":
        return _parse_cargo_lock(lockfile)
    if ecosystem == "pypi":
        return _parse_python_lock(lockfile)
    return []


def _parse_package_json(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    packages = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, version in payload.get(section, {}).items():
            packages.append({"name": name, "version": str(version), "scope": section})
    return packages


def _parse_python_manifest(path: Path) -> list[dict[str, Any]]:
    name = path.name.lower()
    packages = []
    if name == "requirements.txt":
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = re.match(r"([A-Za-z0-9_.-]+)\s*([<>=!~].+)?", stripped)
            if match:
                packages.append({"name": match.group(1), "version": (match.group(2) or "").strip() or None, "scope": "requirements"})
    elif name == "pipfile.lock":
        payload = json.loads(path.read_text(encoding="utf-8"))
        for section in ("default", "develop"):
            for dep_name, spec in payload.get(section, {}).items():
                version = spec.get("version") if isinstance(spec, dict) else str(spec)
                packages.append({"name": dep_name, "version": version, "scope": f"pipenv:{section}"})
    elif name == "pipfile":
        current_scope = None
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                current_scope = stripped.strip("[]")
                continue
            if current_scope in {"packages", "dev-packages"} and "=" in stripped:
                dep_name, spec = [part.strip() for part in stripped.split("=", 1)]
                packages.append({"name": dep_name.strip('"\''), "version": spec.strip('"\''), "scope": f"pipenv:{current_scope}"})
    elif name == "pyproject.toml" and tomllib is not None:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
        project = payload.get("project", {})
        for dep in project.get("dependencies", []):
            pkg = dep.split(";")[0].strip()
            match = re.match(r"([A-Za-z0-9_.-]+)\s*([<>=!~].+)?", pkg)
            if match:
                packages.append({"name": match.group(1), "version": (match.group(2) or "").strip() or None, "scope": "project"})
        for scope, deps in project.get("optional-dependencies", {}).items():
            for dep in deps:
                pkg = dep.split(";")[0].strip()
                match = re.match(r"([A-Za-z0-9_.-]+)\s*([<>=!~].+)?", pkg)
                if match:
                    packages.append({"name": match.group(1), "version": (match.group(2) or "").strip() or None, "scope": f"optional:{scope}"})
        poetry = payload.get("tool", {}).get("poetry", {})
        for scope_name in ("dependencies", "group"):
            if scope_name == "dependencies":
                for dep_name, spec in poetry.get("dependencies", {}).items():
                    if dep_name.lower() == "python":
                        continue
                    version = spec.get("version") if isinstance(spec, dict) else str(spec)
                    packages.append({"name": dep_name, "version": version, "scope": "poetry"})
            else:
                for group_name, group_meta in poetry.get("group", {}).items():
                    for dep_name, spec in group_meta.get("dependencies", {}).items():
                        version = spec.get("version") if isinstance(spec, dict) else str(spec)
                        packages.append({"name": dep_name, "version": version, "scope": f"poetry:{group_name}"})
    return packages


def _parse_cargo_toml(path: Path) -> list[dict[str, Any]]:
    if tomllib is None:
        return []
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    packages = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, spec in payload.get(section, {}).items():
            version = spec.get("version") if isinstance(spec, dict) else str(spec)
            packages.append({"name": name, "version": version, "scope": section})
    return packages


def _parse_pom_xml(path: Path) -> list[dict[str, Any]]:
    tree = ET.parse(path)
    root = tree.getroot()
    ns = {"m": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
    deps = root.findall(".//m:dependency", ns) if ns else root.findall(".//dependency")
    packages = []
    for dep in deps:
        def _find_text(tag: str) -> str | None:
            node = dep.find(f"m:{tag}", ns) if ns else dep.find(tag)
            return node.text.strip() if node is not None and node.text else None
        group_id = _find_text("groupId")
        artifact_id = _find_text("artifactId")
        version = _find_text("version")
        if artifact_id:
            packages.append({"name": f"{group_id}:{artifact_id}" if group_id else artifact_id, "version": version, "scope": "dependency"})
    return packages


def _parse_package_lock(path: Path) -> list[dict[str, Any]]:
    if path.name.lower() == "yarn.lock":
        return _parse_yarn_lock(path)
    if path.name.lower() == "pnpm-lock.yaml":
        return _parse_pnpm_lock(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    packages = []
    if "packages" in payload:
        for name, meta in payload["packages"].items():
            package_name = meta.get("name") or name.removeprefix("node_modules/")
            if package_name:
                packages.append({"name": package_name, "version": meta.get("version"), "scope": "transitive"})
    elif "dependencies" in payload:
        for name, meta in payload["dependencies"].items():
            packages.append({"name": name, "version": meta.get("version"), "scope": "transitive"})
    return packages


def _parse_cargo_lock(path: Path) -> list[dict[str, Any]]:
    if tomllib is None:
        return []
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    return [{"name": pkg["name"], "version": pkg.get("version"), "scope": "transitive"} for pkg in payload.get("package", [])]


def _parse_python_lock(path: Path) -> list[dict[str, Any]]:
    name = path.name.lower()
    packages = []
    if name.endswith(".txt"):
        return _parse_python_manifest(path)
    if name == "pipfile.lock":
        return _parse_python_manifest(path)
    if name == "poetry.lock":
        current_name = None
        current_version = None
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("name ="):
                current_name = stripped.split("=", 1)[1].strip().strip('"')
            elif stripped.startswith("version ="):
                current_version = stripped.split("=", 1)[1].strip().strip('"')
            elif stripped == "" and current_name:
                packages.append({"name": current_name, "version": current_version, "scope": "transitive"})
                current_name = None
                current_version = None
        if current_name:
            packages.append({"name": current_name, "version": current_version, "scope": "transitive"})
    return packages


def _parse_yarn_lock(path: Path) -> list[dict[str, Any]]:
    packages = []
    current_name = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith(" ") and line.endswith(":"):
            current_name = line.split("@", 1)[0].strip().strip('"').strip("'")
        elif line.strip().startswith("version ") and current_name:
            version = line.split(" ", 1)[1].strip().strip('"')
            packages.append({"name": current_name, "version": version, "scope": "transitive"})
    return packages


def _parse_pnpm_lock(path: Path) -> list[dict[str, Any]]:
    packages = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("/") and ":" in stripped:
            package_spec = stripped.split(":", 1)[0].lstrip("/")
            if "@" in package_spec:
                name, version = package_spec.rsplit("@", 1)
                packages.append({"name": name, "version": version, "scope": "transitive"})
    return packages


def _load_advisories() -> list[dict[str, Any]]:
    global _ADVISORY_CACHE
    if _ADVISORY_CACHE is None:
        path = Path(__file__).with_name("advisories.json")
        payload = json.loads(path.read_text(encoding="utf-8"))
        _ADVISORY_CACHE = payload
    return _ADVISORY_CACHE.get("advisories", [])


def _normalize_version(version: str | None) -> tuple[int, ...]:
    if not version:
        return tuple()
    cleaned = version.strip()
    cleaned = cleaned.lstrip("^~<>=! ")
    cleaned = re.split(r"[+-]", cleaned)[0]
    parts = []
    for token in cleaned.split("."):
        match = re.match(r"(\d+)", token)
        if not match:
            break
        parts.append(int(match.group(1)))
    return tuple(parts)


def _compare_versions(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    max_len = max(len(left), len(right))
    padded_left = left + (0,) * (max_len - len(left))
    padded_right = right + (0,) * (max_len - len(right))
    if padded_left < padded_right:
        return -1
    if padded_left > padded_right:
        return 1
    return 0


def _matches_constraint(version: str | None, constraint: str) -> bool:
    if constraint == "*" or not constraint:
        return True
    normalized = _normalize_version(version)
    target = _normalize_version(constraint)
    if constraint.startswith("<="):
        return _compare_versions(normalized, target) <= 0
    if constraint.startswith(">="):
        return _compare_versions(normalized, target) >= 0
    if constraint.startswith("<"):
        return _compare_versions(normalized, target) < 0
    if constraint.startswith(">"):
        return _compare_versions(normalized, target) > 0
    if constraint.startswith("=="):
        return _compare_versions(normalized, target) == 0
    return normalized == target


def _advisories_for(package_name: str, ecosystem: str, version: str | None) -> list[dict[str, Any]]:
    matches = []
    for advisory in _load_advisories():
        if advisory["package"].lower() != package_name.lower():
            continue
        if advisory.get("ecosystem") not in {None, ecosystem}:
            continue
        if any(_matches_constraint(version, constraint) for constraint in advisory.get("affected", ["*"])):
            matches.append(
                {
                    "id": advisory["id"],
                    "issue": advisory["summary"],
                    "severity": advisory["severity"],
                    "reference": advisory["reference"],
                }
            )
    return matches


def _package_name_tokens(name: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", name.lower()) if token}


def _enrich_package(package: dict[str, Any], ecosystem: str) -> dict[str, Any]:
    name = package["name"]
    lower = name.lower()
    tokens = _package_name_tokens(name)
    crypto_usage: list[str] = []
    known_vulns: list[dict[str, Any]] = []
    pq_safe = False
    upgrade_path = "Manual review required."

    for heuristic in DEPENDENCY_HEURISTICS:
        match_token = heuristic["match"].lower()
        if match_token in lower and (match_token in tokens or lower == match_token or lower.endswith(f"/{match_token}")):
            crypto_usage = heuristic["usage"]
            pq_safe = heuristic["pq_safe"]
            upgrade_path = heuristic["upgrade"]
            break

    for vuln_hint in KNOWN_VULN_HINTS:
        match_token = vuln_hint["match"].lower()
        if match_token in lower and (match_token in tokens or lower == match_token or lower.endswith(f"/{match_token}")):
            known_vulns.append(
                {
                    "issue": vuln_hint["issue"],
                    "severity": vuln_hint["severity"],
                    "reference": vuln_hint["reference"],
                }
            )

    known_vulns.extend(_advisories_for(name, ecosystem, package.get("version")))
    deduped_vulns = []
    seen_vulns = set()
    for vuln in known_vulns:
        key = (vuln.get("id"), vuln["issue"], vuln["severity"])
        if key in seen_vulns:
            continue
        seen_vulns.add(key)
        deduped_vulns.append(vuln)
    known_vulns = sorted(deduped_vulns, key=lambda item: (-SEVERITY_ORDER.get(item["severity"], 0), item.get("id", item["issue"])))

    if not crypto_usage and tokens.intersection({"crypto", "tls", "ssl", "jwt", "jose", "x509", "cert", "hash", "sign"}):
        crypto_usage = ["possible cryptographic functionality"]
        upgrade_path = "Review package APIs for weak algorithm defaults and PQ impact."

    return {
        "name": name,
        "version": package.get("version"),
        "crypto_usage": crypto_usage,
        "known_vulns": known_vulns,
        "pq_safe": pq_safe,
        "upgrade_path": upgrade_path,
    }


def assess_pq_risk(services: list[dict[str, Any]], crqc_horizon_years: int = 10, migration_lead_years: int = 2) -> dict[str, Any]:
    ranked: list[dict[str, Any]] = []
    sensitivity_weight = {"low": 10, "medium": 25, "high": 40, "critical": 55}

    for service in services:
        algorithms = service.get("algorithms", [])
        longevity = int(service.get("data_longevity_years", 0))
        sensitivity = service.get("data_sensitivity", "low")
        base = sensitivity_weight.get(sensitivity, 10)
        pq_penalty = 0
        rationale_parts = []
        for algorithm in algorithms:
            classification = classify_algorithm(algorithm, "key_exchange")
            if classification["pq_security_bits"] == 0:
                pq_penalty += 12
                rationale_parts.append(f"{algorithm} lacks PQ resistance")
            elif classification["pq_security_bits"] < 128:
                pq_penalty += 6
                rationale_parts.append(f"{algorithm} has limited PQ margin")
        if longevity >= crqc_horizon_years:
            pq_penalty += 20
            rationale_parts.append("data longevity extends past the assumed CRQC horizon")
        elif longevity + migration_lead_years >= crqc_horizon_years:
            pq_penalty += 10
            rationale_parts.append("migration window overlaps the assumed CRQC horizon")

        score = max(0, min(100, base + pq_penalty))
        if score >= 80:
            band, urgency = "critical", "start immediately"
        elif score >= 60:
            band, urgency = "high", "prioritize this year"
        elif score >= 35:
            band, urgency = "medium", "plan next"
        else:
            band, urgency = "low", "monitor"
        ranked.append(
            {
                "name": service["name"],
                "pq_risk_score": score,
                "risk_band": band,
                "urgency": urgency,
                "rationale": "; ".join(rationale_parts) or "short-lived data with limited PQ exposure",
            }
        )

    ranked.sort(key=lambda item: item["pq_risk_score"], reverse=True)
    return {"services": ranked}


def generate_inventory_from_runs(runs: list[dict[str, Any]], group_by: str = "severity") -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    timestamps: list[str] = []
    total_findings = 0

    for run in runs:
        timestamps.append(run["timestamp"])
        items = run["result"].get("findings", [])
        total_findings += len(items)
        for finding in items:
            grouped[_grouping_key(finding, group_by)].append(finding)

    summary_stats = {
        "total_findings": total_findings,
        "critical": sum(1 for items in grouped.values() for item in items if item.get("severity") == "critical"),
        "high": sum(1 for items in grouped.values() for item in items if item.get("severity") == "high"),
        "medium": sum(1 for items in grouped.values() for item in items if item.get("severity") == "medium"),
        "low": sum(1 for items in grouped.values() for item in items if item.get("severity") == "low"),
    }

    return {
        "inventory": {
            "summary_stats": summary_stats,
            "grouped_findings": dict(sorted(grouped.items(), key=lambda item: item[0])),
            "coverage_metadata": {"source_runs": len(runs)},
            "scan_timestamps": sorted(timestamps),
        }
    }


def _grouping_key(finding: dict[str, Any], group_by: str) -> str:
    if group_by == "algorithm":
        return str(finding.get("algo", "unknown"))
    if group_by == "service":
        return str(finding.get("service", "unassigned"))
    if group_by == "file":
        return str(finding.get("file", "unknown"))
    return str(finding.get("severity", "unknown"))


def build_migration_roadmap(inventory: dict[str, Any], team_size: int = 3, include_patches: bool = True, target_compliance: list[str] | None = None) -> dict[str, Any]:
    all_findings = [finding for group in inventory["grouped_findings"].values() for finding in group]
    severity_buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in all_findings:
        severity_buckets[finding.get("severity", "low")].append(finding)

    target_compliance = target_compliance or []
    phases: list[dict[str, Any]] = []
    for severity, priority in [("critical", 1), ("high", 2), ("medium", 3), ("low", 4)]:
        bucket = severity_buckets.get(severity, [])
        if not bucket:
            continue
        effort = max(1, round(len(bucket) * {"critical": 1.5, "high": 1.0, "medium": 0.5, "low": 0.25}[severity] / max(team_size, 1)))
        patches = []
        if include_patches:
            for finding in bucket[:5]:
                patches.append(
                    {
                        "file": finding.get("file"),
                        "before": finding.get("context_snippet") or finding.get("current_value"),
                        "after": finding.get("suggested_replacement") or finding.get("compliant_value"),
                    }
                )
        phases.append(
            {
                "priority": priority,
                "findings_addressed": len(bucket),
                "effort_weeks": effort,
                "patch_examples": patches,
                "compliance_unlocked": target_compliance,
                "pq_risk_reduction_delta": {"critical": 30, "high": 20, "medium": 10, "low": 5}[severity],
            }
        )
    return {"phases": phases}


def build_delta_report(baseline: dict[str, Any], current: dict[str, Any], highlight_regressions: bool = True) -> dict[str, Any]:
    baseline_index = _inventory_index(baseline["grouped_findings"])
    current_index = _inventory_index(current["grouped_findings"])
    resolved = sorted(baseline_index - current_index)
    regressed = sorted(current_index - baseline_index)
    baseline_score = _inventory_pq_score(baseline)
    current_score = _inventory_pq_score(current)
    return {
        "resolved": resolved,
        "regressed": regressed if highlight_regressions else [],
        "new_findings": regressed if highlight_regressions else [],
        "pq_score_delta": current_score - baseline_score,
        "compliance_delta": {
            "critical_delta": current["summary_stats"]["critical"] - baseline["summary_stats"]["critical"],
            "high_delta": current["summary_stats"]["high"] - baseline["summary_stats"]["high"],
        },
        "summary_narrative": _delta_narrative(resolved, regressed, current_score - baseline_score),
    }


def _inventory_index(grouped: dict[str, list[dict[str, Any]]]) -> set[str]:
    index = set()
    for findings in grouped.values():
        for finding in findings:
            index.add(f"{finding.get('file')}:{finding.get('line')}:{finding.get('algo', finding.get('key_path'))}:{finding.get('severity')}")
    return index


def _inventory_pq_score(inventory: dict[str, Any]) -> int:
    stats = inventory["summary_stats"]
    return max(0, 100 - (stats["critical"] * 10 + stats["high"] * 6 + stats["medium"] * 3 + stats["low"]))


def _delta_narrative(resolved: list[str], regressed: list[str], pq_score_delta: int) -> str:
    if not resolved and not regressed:
        return "No material cryptographic changes were detected between inventories."
    if pq_score_delta > 0:
        return f"Security posture improved with {len(resolved)} resolved findings and PQ score delta {pq_score_delta}."
    if pq_score_delta < 0:
        return f"Security posture regressed with {len(regressed)} new findings and PQ score delta {pq_score_delta}."
    return f"Mixed change set: {len(resolved)} resolved and {len(regressed)} newly introduced findings."

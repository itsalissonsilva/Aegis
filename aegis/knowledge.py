from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AlgorithmProfile:
    canonical_name: str
    use_case: str
    classical_security_bits: int | None
    pq_security_bits: int
    status: str
    severity: str
    replacement: str
    migration_complexity: str
    nist_reference: str
    suggested_replacement: str


ALGORITHM_PROFILES: dict[str, AlgorithmProfile] = {
    "md5": AlgorithmProfile("MD5", "hashing", 0, 0, "prohibited", "critical", "SHA-256 or SHA-3-256", "trivial", "NIST SP 800-131A Rev. 2", "Replace MD5 with SHA-256 or SHA-3-256."),
    "sha1": AlgorithmProfile("SHA-1", "hashing", 63, 0, "deprecated", "high", "SHA-256, SHA-384, or SHA-3-256", "trivial", "NIST SP 800-131A Rev. 2", "Replace SHA-1 with SHA-256 or stronger."),
    "des": AlgorithmProfile("DES", "symmetric_enc", 56, 28, "prohibited", "critical", "AES-256-GCM", "moderate", "NIST SP 800-131A Rev. 2", "Migrate DES to AES-GCM."),
    "3des": AlgorithmProfile("3DES", "symmetric_enc", 112, 56, "deprecated", "high", "AES-256-GCM", "moderate", "NIST SP 800-131A Rev. 2", "Replace 3DES with AES-GCM."),
    "aes-128-cbc": AlgorithmProfile("AES-128-CBC", "symmetric_enc", 128, 64, "deprecated", "medium", "AES-256-GCM", "moderate", "NIST SP 800-38A / prefer AEAD modes", "Prefer AES-GCM or ChaCha20-Poly1305 over CBC."),
    "aes-256-cbc": AlgorithmProfile("AES-256-CBC", "symmetric_enc", 256, 128, "approved", "low", "AES-256-GCM", "moderate", "NIST SP 800-38A / prefer AEAD modes", "Consider AES-256-GCM for authenticated encryption."),
    "aes-128-gcm": AlgorithmProfile("AES-128-GCM", "symmetric_enc", 128, 64, "approved", "low", "AES-256-GCM", "trivial", "NIST SP 800-38D", "AES-128-GCM is acceptable; AES-256-GCM increases margin."),
    "aes-256-gcm": AlgorithmProfile("AES-256-GCM", "symmetric_enc", 256, 128, "approved", "low", "AES-256-GCM", "trivial", "NIST SP 800-38D", "No replacement required."),
    "chacha20-poly1305": AlgorithmProfile("ChaCha20-Poly1305", "symmetric_enc", 256, 128, "approved", "low", "ChaCha20-Poly1305", "trivial", "Widely accepted AEAD; deployment-specific", "No replacement required."),
    "rsa-1024": AlgorithmProfile("RSA-1024", "signature", 80, 0, "prohibited", "critical", "RSA-3072 or ML-DSA hybrid transition", "hard", "NIST SP 800-131A Rev. 2", "Replace RSA-1024 with RSA-3072+ or PQ-capable designs."),
    "rsa-2048": AlgorithmProfile("RSA-2048", "signature", 112, 0, "approved", "medium", "RSA-3072, ECDSA P-384, or ML-DSA transition", "hard", "NIST SP 800-131A Rev. 2", "Acceptable today, but prioritize PQ transition for long-lived data."),
    "rsa-3072": AlgorithmProfile("RSA-3072", "signature", 128, 0, "approved", "low", "ML-DSA transition where appropriate", "hard", "NIST SP 800-131A Rev. 2", "No immediate classical replacement required."),
    "ecdh-p256": AlgorithmProfile("ECDH-P256", "key_exchange", 128, 0, "approved", "medium", "Hybrid X25519/ML-KEM-768 or ECDH with PQ plan", "hard", "NIST SP 800-56A Rev. 3", "Plan hybrid key exchange for long-lived secrets."),
    "ecdsa-p256": AlgorithmProfile("ECDSA-P256", "signature", 128, 0, "approved", "medium", "Hybrid classical + ML-DSA transition", "hard", "FIPS 186-5", "Maintain short-term use, but design PQ signature migration."),
    "x25519": AlgorithmProfile("X25519", "key_exchange", 128, 0, "approved", "medium", "Hybrid X25519/ML-KEM-768", "hard", "Industry accepted; PQ transition advised", "Adopt hybrid key exchange for long-lived confidentiality."),
    "hmac-sha256": AlgorithmProfile("HMAC-SHA256", "mac", 128, 128, "approved", "low", "HMAC-SHA256", "trivial", "FIPS 198-1", "No replacement required."),
    "pbkdf2": AlgorithmProfile("PBKDF2", "kdf", 128, 128, "approved", "medium", "Argon2id or tuned PBKDF2 iterations", "moderate", "NIST SP 800-132", "Prefer Argon2id where available or increase PBKDF2 cost."),
    "argon2": AlgorithmProfile("Argon2id", "kdf", 128, 128, "approved", "low", "Argon2id", "trivial", "Industry recommended password hashing", "No replacement required."),
    "ml-kem-768": AlgorithmProfile("ML-KEM-768", "key_exchange", 192, 192, "approved", "low", "ML-KEM-768", "moderate", "FIPS 203", "No replacement required."),
    "ml-dsa-65": AlgorithmProfile("ML-DSA-65", "signature", 192, 192, "approved", "low", "ML-DSA-65", "moderate", "FIPS 204", "No replacement required."),
}


LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".js": "js",
    ".jsx": "js",
    ".ts": "js",
    ".tsx": "js",
    ".c": "c",
    ".h": "c",
    ".cc": "c",
    ".cpp": "c",
    ".hpp": "c",
}


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

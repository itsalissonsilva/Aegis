# Aegis

Aegis is a cryptography audit MCP server for finding weak cryptography, mapping
where cryptography is used, checking post-quantum migration posture, and
building remediation inventories and roadmaps.

It is built to work well on real repos and real endpoints:

- source code and documentation scans
- config audits
- dependency crypto fingerprinting
- live TLS probing
- crypto inventory generation
- migration planning and delta tracking

## Tools

### Discovery

- `scan_codebase`
  - Static scan for cryptographic algorithms, JOSE/JWT algorithm identifiers,
    weak key guidance, and PQ algorithm references in source and docs.
  - Example repos:
    - `jmw5598/node-express-jwt-example`
    - `open-quantum-safe/oqs-provider`
    - `GiacomoPope/kyber-py`
- `probe_tls_endpoint`
  - Active TLS probe for direct TLS and upgrade-based protocols.
  - Supported modes today: `none`, `smtp`, `imap`, `ftp`, `postgres`,
    `mysql`, `ldap`, `pop3`, `xmpp`.
  - Example live target tested: `github.com:443`
- `audit_config`
  - Checks crypto-related settings in SSH, nginx, OpenSSL, JWT-style configs,
    and Kubernetes Secret-style files.
  - Example repo:
    - `jmw5598/node-express-jwt-example` with `config/jwt.js`
- `scan_dependencies`
  - Parses common manifests and lockfiles and annotates packages with crypto
    usage, local advisory hits, PQ posture hints, and upgrade guidance.
  - Example repos:
    - `jmw5598/node-express-jwt-example` via `package.json`
    - `GiacomoPope/kyber-py` via `pyproject.toml`

### Analysis

- `assess_pq_risk`
- `classify_algorithm`

### Output

- `generate_inventory`
- `get_migration_roadmap`
- `get_delta_report`

## What It Catches Well

- weak algorithms like `MD5`, `SHA-1`, `DES`, `3DES`
- classical crypto used in long-term contexts like `RSA-2048`, `ECDH-P256`,
  `X25519`
- JWT algorithm configuration like `RS256`, `HS256`, `none`
- weak guidance in docs like `512-bit RSA`
- PQ-positive references like `ML-KEM-768` and `ML-DSA-65`
- TLS version / cipher posture on live endpoints

## Current Limits

- OCSP checking is best-effort and strongest on Windows
- dependency advisories are local/static, not pulled from live feeds
- cipher enumeration is coarse rather than exhaustive
- findings are strongest for explicit crypto references; deeply abstracted usage
  may still need better language-specific rules

## Install

### Option 1: local editable install

```powershell
cd C:\path\to\Aegis
python -m venv .venv
.venv\Scripts\activate
python -m pip install -U pip
python -m pip install -e .
```

Then the MCP server can be started with:

```powershell
aegis
```

### Option 2: run directly from source

```powershell
cd C:\path\to\Aegis
python -m aegis.server
```

## Cursor Setup

Add Aegis as an MCP server in Cursor. A practical Windows config looks like:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "python",
      "args": [
        "-m",
        "aegis.server"
      ],
      "cwd": "C:\\path\\to\\Aegis"
    }
  }
}
```

If you installed the package into a dedicated venv, point Cursor at that Python
interpreter instead:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "C:\\path\\to\\Aegis\\.venv\\Scripts\\python.exe",
      "args": [
        "-m",
        "aegis.server"
      ],
      "cwd": "C:\\path\\to\\Aegis"
    }
  }
}
```

## Example Workflow

### Audit a repo

1. Clone the repo locally.
2. Run `scan_codebase` on the repo root.
3. Run `scan_dependencies` on the repo manifest.
4. Run `audit_config` on config folders or files.
5. Generate an inventory from those scan IDs.
6. Generate a roadmap from the inventory.

Example prompts in Cursor:

- `Run scan_codebase on C:\repo\my-app with low severity`
- `Run scan_dependencies on C:\repo\my-app\package.json`
- `Audit configs under C:\repo\my-app\config`
- `Generate an inventory from the last three scans grouped by severity`
- `Create a migration roadmap from that inventory`

Repos we tested this workflow against:

- `jmw5598/node-express-jwt-example`
  - surfaced weak `512-bit RSA` guidance and `RS256` JWT config
- `open-quantum-safe/oqs-provider`
  - surfaced mixed classical and PQ references like `X25519`, `RSA-2048`,
    `ML-KEM-768`, and `ML-DSA-65`
- `GiacomoPope/kyber-py`
  - surfaced strong PQ-positive `ML-KEM-768` references

### Probe a live endpoint

Examples:

- `Probe github.com on port 443`
- `Probe mail.example.com on port 25 with smtp STARTTLS`
- `Probe db.example.com on port 5432 with postgres negotiation`

## Example Output

Real findings Aegis surfaced on a JWT demo repo:

```json
[
  {
    "file": "README.md",
    "algo": "Weak Key Size Guidance",
    "severity": "critical",
    "context_snippet": "A 512bit key size should be fine."
  },
  {
    "file": "config/jwt.js",
    "algo": "JWT-RS256",
    "severity": "medium",
    "context_snippet": "algorithm: 'RS256'"
  }
]
```

Real findings Aegis surfaced on a PQ-focused repo:

```json
[
  {
    "file": "README.md",
    "algo": "ML-KEM-768",
    "severity": "low"
  },
  {
    "file": "README.md",
    "algo": "ML-DSA-65",
    "severity": "low"
  }
]
```

## Tested

The local automated suite currently covers:

- contract shapes for all core tools
- inventory / roadmap / delta flow
- dependency parsing across npm, yarn, pnpm, Poetry, Pipenv, Cargo, and Maven
- direct TLS failure handling
- `smtp`, `imap`, `ftp`, `postgres`, `mysql`, `ldap`, `pop3`, and `xmpp`
  upgrade flows via local protocol fixtures

Run tests with:

```powershell
python -m unittest discover -s tests -v
```

## Repo Layout

- `aegis/server.py`
- `aegis/engine.py`
- `aegis/knowledge.py`
- `aegis/state.py`
- `tests/test_contracts.py`

## Next Improvements

- richer language-aware code rules for JS, Java, and Go crypto APIs
- cleaner remediation text per finding type
- live advisory feeds for dependency scanning
- stronger cross-platform OCSP and certificate-chain validation

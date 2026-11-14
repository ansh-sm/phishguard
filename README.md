# PhishGuard SOC 🛡️
### Enterprise-Grade Automated Phishing Detection & Threat Intelligence Platform

PhishGuard SOC is a high-performance, modular email security and digital forensics engine designed to mirror the workflow of a Tier-2/Tier-3 Security Operations Center (SOC) incident responder.

---

## 🚀 Key Architectural Capabilities

- **RFC 5322/2045 Ingestion Engine**: Authentic parsing of headers, recursive MIME parts, nested attached emails (`message/rfc822`), and encoding normalizations.
- **Header Forensics & Traceability**:
  - Full reverse `Received:` hop reconstruction, latency delta calculation, and private vs. public IP boundary detection.
  - Authentication status parsing (`Authentication-Results`, `Received-SPF` for SPF, DKIM, and DMARC).
  - Impersonation detection: Display name spoofing, `Reply-To` mismatches, IDN Homographs, and Levenshtein distance checks against enterprise brands.
- **URL & Content Deception Engine**:
  - Plaintext and HTML link extraction, automated defanging (`hxxp[s]://...`).
  - Anchor text vs `href` destination mismatch detection.
  - De-obfuscation for hex/octal/percent-encoded URLs and IP literal hosts.
  - QR Code extraction & Quishing payload decoder.
- **Resilient Threat Intelligence**:
  - Asynchronous queries to URLhaus (Abuse.ch) and PhishTank.
  - Local SQLite cache with TTL to eliminate rate-limit bottlenecks.
  - Full offline/mock mode for isolated air-gapped environments.
- **Attachment Forensics**:
  - Multi-hash calculation (MD5, SHA1, SHA256).
  - True file-type identification (magic bytes).
  - Double-extension detection and macro/script payload detection.
- **Multi-Vector Scoring & SOC Reporting**:
  - Weighted 0–100 risk scoring with transparent sub-scores.
  - Automated plain-English SOC analyst verdict and containment playbook.
  - Color-coded Rich terminal CLI, SIEM-compatible JSON, and self-contained HTML reports.

---

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/your-org/phishguard.git
cd phishguard

# Setup virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\activate

# Install with dependencies
pip install -e ".[dev]"
```

## 📖 Usage

```bash
# Scan a single .eml file
phishguard scan samples/suspicious_credential_harvest.eml

# Output SIEM-compatible JSON
phishguard scan samples/suspicious_credential_harvest.eml --json
```

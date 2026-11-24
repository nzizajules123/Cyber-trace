# CyberTrace

CyberTrace is a defensive digital forensics and cyber investigation platform designed for **CyberTrace Local** (private forensic laboratories) and **CyberTrace Cloud** (multi-organization deployments).

## Key Capabilities
* **Authentication, Organizations & RBAC**: Argon2id password hashing, DB-backed revocable sessions, RFC 6238 TOTP MFA, password recovery, organization isolation, and 6 backend-enforced roles (`SYSTEM_ADMIN`, `ORG_ADMIN`, `LEAD_INVESTIGATOR`, `INVESTIGATOR`, `EVIDENCE_ANALYST`, `READ_ONLY_AUDITOR`).
* **Case Management**: Full lifecycle CRUD, search/filter/pagination, investigator notes, soft-delete archival, camelCase audit diffs, and live metrics.
* **Evidence Vault & Chain of Custody**: Pluggable `EvidenceStorage` abstraction with path-traversal protection, automatic SHA-256/SHA-512/MD5 hashing, on-disk SHA-256 verification, audited `nosniff` downloads, and hash-chained tamper-evident Chain of Custody.
* **Digital Footprint (URL Research)**: SSRF-guarded website research inspecting DNS, TLS certificates, redirect chains, HTTP security headers, HTML forms/phishing indicators, IOCs, and optional Evidence Vault sealing.
* **Log Analysis, Event Correlation & Findings**: Multi-format parser (JSON/JSONL, CSV, Syslog/SSH, Apache/Nginx), IOC extraction, automated detection rules, cross-artifact correlation, unified timeline, and manual/automated finding triage.
* **Evidence-Backed AI Assistant & PDF Reports**: Local-first AI case synthesis (never transmits external data by default, cites real records) and court-ready ReportLab PDF & JSON dossiers.

## Quick Start (Local)
See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for full setup instructions (SQLite quick-start and Docker/MySQL 8.4).

```powershell
# Backend
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

## Documentation
* [Project Audit](docs/PROJECT_AUDIT.md)
* [Architecture](docs/ARCHITECTURE.md)
* [Security](docs/SECURITY.md)
* [API Reference](docs/API.md)
* [Testing](docs/TESTING.md)
* [Deployment](docs/DEPLOYMENT.md)
* [Roadmap](docs/ROADMAP.md)

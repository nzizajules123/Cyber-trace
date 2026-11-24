# CyberTrace — Roadmap

## Completed Milestones
* **Phase 1–2**: Modular monolith foundation, Argon2id authentication, DB-backed revocable sessions, TOTP MFA, password recovery, Organizations, 6-role backend-enforced RBAC, organization isolation, Case Notes, System Audit Logs.
* **Phase 3**: `EvidenceStorage` abstraction, path-traversal containment, SHA-256/SHA-512/MD5 vault ingestion, on-disk SHA-256 integrity re-verification, audited `nosniff` downloads, tamper-evident hash-chained Chain of Custody.
* **Phase 4**: SSRF-safe Digital Footprint URL research, multi-format Log Analysis & IOC extraction, automated Detection Rules, Event Correlation engine, Unified Case Timeline, manual & automated Findings triage, controlled evidence-backed AI Investigation Assistant, ReportLab PDF & JSON reports.
* **Phase 5–6**: Full React workspace (zero placeholder pages), Vitest frontend suite, Pytest security/RBAC suite, Ruff linting, and engineering documentation.

## Next Recommended Priorities
1. **Object Storage Adapter (`storage/s3.py`)**: Implement S3/MinIO/GCS backend for `EvidenceStorage` in CyberTrace Cloud deployments.
2. **Redis-Backed Rate Limiting & SMTP Delivery**: Replace in-memory rate limiter for multi-worker horizontal scaling and integrate SMTP/Transactional email for Cloud password recovery.
3. **Hybrid Local ↔ Cloud Sync Worker**: Build explicit, investigator-approved metadata synchronization using `sync_uuid` and `sync_version` with conflict resolution UI.
4. **Expanded Forensic Parsers**: Add Windows EVTX binary parser, PCAP summary extraction, and STIX 2.1 / MISP IOC export.
5. **E2E CI Pipeline**: Add GitHub Actions workflow running `pytest`, `ruff`, `alembic`, `vitest`, and `vite build` on every pull request.

# CyberTrace — System Architecture

## 1. High-Level Modular Monolith
CyberTrace uses a clean **modular monolith** architecture designed to operate identically in **CyberTrace Local** (air-gapped/private forensic labs) and **CyberTrace Cloud** (centralized multi-organization deployments).

```text
frontend/ (React 19 + Vite 6 + React Router v7 + Tailwind CSS v4)
  ├── src/context/AuthContext.jsx      # Session state, /auth/me hydration, 401 handling
  ├── src/services/apiClient.js        # Unified HTTP client (Bearer auth, timeouts, errors)
  ├── src/services/{cases,dashboard,forensics}Api.js
  └── src/components/                  # Full workspace + Auth + Forensics + Management pages

backend/app/ (FastAPI + SQLAlchemy 2.0 + Alembic + MySQL 8 / SQLite)
  ├── api/deps.py                      # AuthContext, Bearer/Cookie auth, 6-role RBAC
  ├── api/v1/                          # auth, cases, dashboard, evidence, analysis, footprint, reports
  ├── core/                            # config.py (pydantic-settings), security.py (Argon2id, TOTP, RateLimiter)
  ├── db/                              # base.py, session.py (lazy pool_pre_ping, MySQL & SQLite)
  ├── models/                          # auth, case, audit, evidence, analysis, footprint
  ├── schemas/                         # Strict Pydantic v2 schemas (camelCase JSON, extra="forbid")
  ├── services/                        # auth, cases, evidence, log_analyzer, correlation, url_research, reports, dashboard
  ├── storage/                         # EvidenceStorage ABC + LocalEvidenceStorage (path-containment)
  └── integrations/                    # Controlled, evidence-backed AI Investigation Assistant
```

## 2. Database & Multi-Tenant Isolation
* Every organization-owned case carries `organization_id` plus hybrid sync metadata (`sync_uuid`, `sync_version`).
* All downstream tables (`evidence_items`, `evidence_verifications`, `custody_events`, `forensic_events`, `forensic_findings`, `url_investigations`, `case_notes`, `audit_logs`) join through `cases.organization_id`, preventing cross-organization reads or writes at the query layer.
* `system_audit_logs` records authentication, RBAC changes, and audited evidence downloads per organization.

## 3. Hybrid Deployment & Synchronization Design
* **Local Mode (`DEPLOYMENT_MODE=LOCAL`)**: Runs with local SQLite or local MySQL 8 and `LocalEvidenceStorage` (`evidence_vault/`). External AI transmission and cloud sync are disabled by default.
* **Cloud Mode (`DEPLOYMENT_MODE=CLOUD`)**: Uses managed MySQL 8, HTTPS `COOKIE_SECURE=true`, and future S3/GCS `EvidenceStorage` adapter.
* **Future Controlled Sync**: Core entities carry `uuid` / `sync_uuid` and `sync_version` integers to support explicit, opt-in investigator-authorized metadata synchronization with optimistic concurrency conflict detection — never automatically uploading raw sensitive evidence files.

# CyberTrace — Project Audit & Baseline Report

**Audit Date:** 2026-11-24  
**Repository Root:** `E:\Cyber-Trace-main\Cyber-Trace-main`

---

## 1. Baseline Automated Checks

| Check | Command | Baseline Result |
| :--- | :--- | :--- |
| Backend Tests | `python -m pytest -v` | **18 passed**, 0 failed (2 deprecation warnings) |
| Frontend Build | `npm run build` | **PASS** (57 modules transformed, 0 errors) |
| Frontend Tests | *(none configured)* | **MISSING** (no Vitest / RTL setup) |
| Linting / Type Checks | *(none configured)* | **MISSING** (no Ruff / ESLint config) |
| Docker / MySQL Local | `docker --version` | Docker CLI not installed on this workstation (SQLite fallback active for local dev; MySQL 8.4 defined in `docker-compose.yml`) |

---

## 2. Existing Architecture

* **Backend (`backend/app/`)**: FastAPI modular monolith with `api/v1/`, `core/`, `db/`, `models/`, `schemas/`, `services/`, plus Alembic migrations (`20261120_01` through `20261123_04`) and `tests/`.
  * Missing target packages: `storage/` (evidence storage abstraction) and `integrations/` (controlled AI / external provider boundary).
* **Frontend (`frontend/src/`)**: React 19 + Vite 6 + React Router v7 + Tailwind CSS v4 + custom dark design system (`styles.css`).
  * Three separate fetch wrappers (`casesApi.js`, `dashboardApi.js`, `forensicsApi.js`) without a unified `apiClient.js` for auth headers, timeouts, or 401 session handling.

---

## 3. Working Functionality (Baseline)

* **Case Management**: Full CRUD, search, status/severity filters, pagination, metrics, soft-delete, camelCase audit history diffs.
* **Evidence Repository & Integrity**: Multipart file upload, SHA-256/SHA-512/MD5 hashing, on-disk SHA-256 re-verification, tamper-evident hash-chained Chain of Custody ledger.
* **Digital Footprint (URL Research)**: SSRF-guarded DNS resolution, `certifi`-backed TLS certificate inspection, HTTP redirect chain & security headers audit, HTML form/link/IOC extraction, risk scoring, automatic vault sealing.
* **Log Analysis, Findings & Timeline**: JSON/JSONL/CSV/Syslog/Web log parser, IOC extraction, 5 automated detection rules, finding triage workflow, unified timeline.
* **Forensic Reports & Live Dashboard**: ReportLab PDF & JSON export, live `/api/v1/dashboard/overview`.

---

## 4. Incomplete Modules & Placeholders

1. **Authentication & Session Management**: Not implemented. No login, registration, Argon2id password hashing, sessions, password recovery, or MFA.
2. **Organizations & RBAC**: Not implemented. No `organizations`, `users`, `organization_memberships`, or cross-organization isolation. All mutations attribute actions to hardcoded `SYSTEM_ACTOR = "system"`.
3. **Frontend Placeholders (`ModulePlaceholder`)**:
   * `/analysis/event-correlation` (Event Correlation)
   * `/investigators` (Investigators & Organization Management)
   * `/audit-logs` (Global System Audit Logs)
   * `/settings` (Profile, MFA, Hybrid/AI Policy Settings)
   * Missing dedicated `/evidence/:evidenceCode` (Evidence Details) and Auth pages (`/login`, `/register`, `/recover-password`).
4. **Case Notes & Secure Evidence Downloads**: No `case_notes` model/endpoints; no audited `GET /api/v1/evidence/{code}/download` endpoint.
5. **AI-Assisted Investigation Intelligence**: Not implemented.
6. **Hybrid Sync Metadata**: No UUID identifiers or sync metadata fields on core tables for hybrid Local ↔ Cloud readiness.

---

## 5. Security Vulnerabilities & Gaps

| Severity | Finding | Remediation Plan |
| :--- | :--- | :--- |
| **CRITICAL** | All `/api/v1/*` endpoints are completely unauthenticated and open to anonymous access. | Implement Argon2id auth, DB-backed revocable sessions, and enforce `get_current_user` + RBAC on all protected routes. |
| **CRITICAL** | No multi-tenant / organization data isolation. | Add `Organization` and `OrganizationMembership` with strict `organization_id` scoping on all queries and mutations. |
| **HIGH** | Hardcoded `"system"` audit actor undermines forensic accountability and chain-of-custody attribution. | Attribute every case, evidence, custody, finding, and report action to the authenticated investigator. |
| **HIGH** | No rate limiting on authentication or URL research endpoints. | Add sliding-window rate limiting on auth and research endpoints. |
| **MEDIUM** | Direct filesystem calls in `services/evidence.py` lack a clean storage abstraction and explicit path-containment check on read/download. | Introduce `backend/app/storage/` with strict `resolve().is_relative_to(root)` containment and `X-Content-Type-Options: nosniff` downloads. |
| **LOW** | Deprecated `status.HTTP_422_UNPROCESSABLE_ENTITY` usage in FastAPI/Starlette. | Replace with `status.HTTP_422_UNPROCESSABLE_CONTENT`. |

---

## 6. Testing Gaps

* Zero frontend automated tests (no Vitest / React Testing Library).
* Zero authentication, authorization, RBAC, or cross-organization isolation security tests.
* No automated linting (`ruff`) run in CI/dev.

---

## 7. Phased Implementation Plan

1. **Phase 1 (Complete)**: Audit repository, record baseline tests/build, create `docs/PROJECT_AUDIT.md`.
2. **Phase 2**: Authentication (Argon2id, sessions, password recovery, MFA architecture), Organizations, 6-role RBAC, organization isolation, Case Notes, System Audit Logs, rate limiting.
3. **Phase 3**: `backend/app/storage/` abstraction + secure audited evidence downloads + path traversal containment.
4. **Phase 4**: Event Correlation engine, manual Findings creation, controlled evidence-backed AI Investigation Assistant (`backend/app/integrations/`), enhanced PDF reports (organization info, methodology, limitations, conclusions).
5. **Phase 5**: Unified frontend `apiClient.js`, `AuthContext`, Login/Register/Recovery pages, and complete all remaining pages (Evidence Details, Event Correlation, Investigators & Organizations, Audit Logs, Settings, AI Assistant panel).
6. **Phase 6**: Security/RBAC pytest suite, Vitest frontend test suite, Ruff linting, full documentation (`ARCHITECTURE.md`, `SECURITY.md`, `API.md`, `TESTING.md`, `DEPLOYMENT.md`, `ROADMAP.md`, updated `README.md`).

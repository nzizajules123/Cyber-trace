# CyberTrace — API Reference (`/api/v1`)

All protected endpoints require `Authorization: Bearer <token>` or the `cybertrace_session` cookie and return standardized error envelopes (`{"error": {"code", "message", "details?"}}`).

## Health
* `GET /health` — Backend liveness.
* `GET /health/ready` — Database connectivity readiness.

## Authentication, Organizations & Investigators
* `POST /api/v1/auth/register` — Register investigator (creates initial org as `SYSTEM_ADMIN` or joins existing org by slug).
* `POST /api/v1/auth/login` — Authenticate with email, password, and optional `totpCode`.
* `POST /api/v1/auth/logout` — Revoke current session.
* `GET /api/v1/auth/me` / `PATCH /api/v1/auth/me` — Read or update investigator profile.
* `POST /api/v1/auth/password-recovery/request` & `/confirm` — Secure password reset workflow.
* `POST /api/v1/auth/mfa/setup` & `/enable` — TOTP MFA enrollment.
* `GET /api/v1/organizations/current` / `PATCH /api/v1/organizations/current` — Manage current organization.
* `GET /api/v1/investigators` / `POST /api/v1/investigators` / `PATCH /api/v1/investigators/{membership_id}` — RBAC member management.
* `GET /api/v1/audit-logs` — Organization-scoped system audit logs.

## Dashboard & Cases
* `GET /api/v1/dashboard/overview` — Live organization dashboard metrics, recent cases, SHA-256 verification checks, activity timeline, and analytics.
* `GET /api/v1/cases` (`q`, `status`, `severity`, `page`, `size`), `GET /api/v1/cases/metrics`
* `POST /api/v1/cases`, `GET /api/v1/cases/{id}`, `PATCH /api/v1/cases/{id}`, `DELETE /api/v1/cases/{id}` (soft-delete)
* `GET /api/v1/cases/{id}/notes`, `POST /api/v1/cases/{id}/notes`

## Evidence Vault, Integrity & Chain of Custody
* `POST /api/v1/evidence/upload` — Multipart ingest with automatic SHA-256/SHA-512/MD5 & genesis custody record.
* `GET /api/v1/evidence`, `GET /api/v1/evidence/{id}`, `GET /api/v1/evidence/{id}/download` (audited, `nosniff`).
* `POST /api/v1/evidence/{id}/verify`, `GET /api/v1/evidence/integrity/summary`.
* `POST /api/v1/evidence/{id}/custody`, `GET /api/v1/evidence/custody/ledger`.

## Analysis, Digital Footprint, Correlation, Findings, AI & Reports
* `POST /api/v1/footprint/research`, `GET /api/v1/footprint`, `GET /api/v1/footprint/{code}`
* `POST /api/v1/analysis/evidence/{id}/analyze`, `GET /api/v1/analysis/events`, `GET /api/v1/analysis/iocs`
* `GET /api/v1/analysis/correlations`
* `GET /api/v1/analysis/findings`, `POST /api/v1/analysis/findings`, `PATCH /api/v1/analysis/findings/{id}`
* `GET /api/v1/analysis/timeline`
* `POST /api/v1/analysis/ai/assist`
* `GET /api/v1/reports/cases/{id}/pdf`, `GET /api/v1/reports/cases/{id}/json`

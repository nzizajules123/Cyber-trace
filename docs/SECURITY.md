# CyberTrace — Security Engineering & Threat Controls

## 1. Authentication & Session Security
* **Password Hashing**: **Argon2id** (`argon2-cffi`, `time_cost=2`, `memory_cost=65536`, `parallelism=2`). Plaintext passwords and password hashes are never returned in API responses.
* **Sessions**: Opaque 256-bit cryptographically random tokens (`secrets.token_urlsafe(32)`) stored only as **SHA-256 digests** in `user_sessions`. Supports instant server-side revocation on logout, password reset, or investigator deactivation. Delivered via Bearer token and `HttpOnly`, `SameSite=Lax` cookie (`Secure` controlled by `COOKIE_SECURE=true` in HTTPS deployments).
* **Multi-Factor Authentication (MFA)**: Built-in RFC 6238 **TOTP** (6-digit codes, ±30s window) configurable in Settings (`/settings`). `mfa_secret` is never exposed after initial setup.
* **Password Recovery**: Single-use, 30-minute expiring SHA-256-hashed reset tokens (`password_reset_tokens`) that revoke all active sessions upon completion.
* **Rate Limiting**: Sliding-window rate limiter on `/api/v1/auth/login`, `/register`, and `/password-recovery/*`.

## 2. Authorization & Organization Isolation
* Backend-enforced 6-role RBAC via `require_roles(...)` in `backend/app/api/deps.py`:
  * `SYSTEM_ADMIN`, `ORG_ADMIN`: Full organization, investigator, case, and evidence control.
  * `LEAD_INVESTIGATOR`, `INVESTIGATOR`: Case CRUD, notes, evidence, analysis, URL research, findings, reports.
  * `EVIDENCE_ANALYST`: Evidence ingest/verify/custody, log analysis, URL research, findings (no case archive/admin).
  * `READ_ONLY_AUDITOR`: Strictly read-only across cases, evidence, findings, timeline, reports, and audit logs (`403` on any mutation).
* Strict `organization_id` scoping on all queries prevents IDOR and cross-tenant data access.

## 3. Evidence & File Handling Security
* `LocalEvidenceStorage.resolve_safe_path()` enforces `resolved.is_relative_to(vault_root)` to block path traversal.
* Upload size capped at 50 MB; empty files rejected (`422`).
* Evidence downloads (`GET /api/v1/evidence/{code}/download`) always set `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, and append both a `CustodyEvent(EXPORTED)` and a `SystemAuditLog(EVIDENCE_DOWNLOADED)`.
* Original acquisition SHA-256 hashes are never overwritten when later verifications detect mismatches.
* **Chain of Custody**: Append-only via application routes, with SHA-256 hash-chaining across entries. Note: database-level records are tamper-evident (tampering breaks the hash chain), not cryptographically impossible for a DB root user to alter.

## 4. Digital Footprint SSRF & AI Data Controls
* URL Research (`services/url_research.py`) validates `http://`/`https://`, resolves DNS before every request and redirect hop, and blocks loopback (`127.0.0.0/8`, `::1`), RFC1918 private, link-local (`169.254.0.0/16`), multicast, and reserved IP ranges.
* AI Investigation Assistant runs 100% locally by default (`externalDataTransmitted: false`) and never transmits evidence to external providers unless both `AI_PROVIDER_ENABLED=true` and `AI_ALLOW_EXTERNAL_DATA=true` are explicitly configured.

## 5. Remaining Security Hardening for Production Internet Exposure
* Replace in-memory rate limiter with Redis-backed rate limiting for multi-worker deployments.
* Add SMTP/email delivery for password recovery in `CLOUD` mode (in `LOCAL` mode the token is returned directly for air-gapped labs).
* Enforce HTTPS termination (Nginx/Caddy/ALB) with `COOKIE_SECURE=true` and strict `CORS_ORIGINS`.

# CyberTrace — Testing & QA Verification

## Running Automated Tests

### Backend (`pytest` + `ruff`)
```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest -v
.\.venv\Scripts\python.exe -m ruff check app
```

### Frontend (`vitest` + `vite build`)
```powershell
cd frontend
npm test
npm run build
```

## Test Coverage Breakdown
1. **Application & Health (`backend/tests/test_app.py`)**: OpenAPI schema availability, `/health` liveness.
2. **Case Management (`backend/tests/test_cases.py`)**: Full lifecycle, audit diff camelCase keys, search/filter/pagination, active/resolved metrics, soft-delete retention, transactional rollback on audit failure, live dashboard summary.
3. **Forensics Pipeline (`backend/tests/test_forensics.py`)**:
   * Evidence upload, SHA-256/SHA-512/MD5 calculation, on-disk SHA-256 verification, **simulated file tamper detection**, hash-chained custody transfer, **simulated custody DB tamper detection**.
   * Multi-format log analysis (SSH brute-force + credential compromise, sudo privilege escalation, web SQLi/path traversal), IOC extraction, finding triage, unified timeline, ReportLab PDF (`%PDF-`) & JSON export.
   * Digital Footprint URL research: SSRF blocking (`127.0.0.1`), DNS/TLS/header/form analysis, cross-domain phishing form detection, Evidence Vault sealing.
4. **Security, Auth, RBAC & Isolation (`backend/tests/test_security_rbac.py`)**:
   * Unauthenticated & forged token rejection (`401`).
   * Cross-organization isolation (`404` / empty lists across Org A vs Org B).
   * `READ_ONLY_AUDITOR` blocked (`403`) from creating/editing/deleting cases or uploading evidence.
   * Password hash & MFA secret never exposed in API responses.
   * TOTP MFA setup/enforcement, session revocation on logout, password recovery token workflow, system audit logs.
   * Case notes, audited evidence download (`X-Content-Type-Options: nosniff`), event correlation, manual finding creation, and evidence-backed AI assistant (`externalDataTransmitted: false`).
5. **Frontend (`frontend/src/__tests__/App.test.jsx`)**:
   * Unauthenticated redirect to `/login`, 401 login error alert rendering, `/register` page validation, authenticated `/cases` live API rendering.

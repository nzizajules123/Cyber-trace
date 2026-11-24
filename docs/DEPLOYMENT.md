# CyberTrace — Deployment Guide (Local & Cloud)

## 1. CyberTrace Local (Quick Start — No Docker Required)
1. Create `backend/.env`:
   ```env
   DATABASE_URL=sqlite:///./cybertrace.db
   CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
   DEPLOYMENT_MODE=LOCAL
   EVIDENCE_VAULT_DIR=evidence_vault
   ```
2. Install backend dependencies, run Alembic migrations, and start FastAPI:
   ```powershell
   cd backend
   python -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -e ".[dev]"
   .\.venv\Scripts\python.exe -m alembic upgrade head
   .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```
3. Install and start the React frontend:
   ```powershell
   cd frontend
   npm install
   npm run dev
   ```
4. Open `http://127.0.0.1:5173`, click **Create investigator account**, and initialize your organization.

## 2. CyberTrace Local / Production with MySQL 8.4 (Docker Compose)
1. Copy `.env.example` to `.env` and `backend/.env` with strong credentials.
2. Start MySQL 8.4:
   ```powershell
   docker compose up -d --wait mysql
   ```
3. Run `alembic upgrade head` and start Uvicorn behind an HTTPS reverse proxy (Nginx / Caddy / Cloud Load Balancer).

## 3. CyberTrace Cloud Hardening Checklist
* Set `DEPLOYMENT_MODE=CLOUD`, `COOKIE_SECURE=true`, and strict `CORS_ORIGINS=https://your-domain.example`.
* Back up both the MySQL database and the `evidence_vault/` volume regularly, verifying SHA-256 hashes post-restore.
* Keep `AI_ALLOW_EXTERNAL_DATA=false` unless your organization's data governance policy explicitly approves external AI providers.

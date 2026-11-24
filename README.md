# CyberTrace

CyberTrace is a defensive digital forensics and cyber investigation platform.
The frontend includes an investigation dashboard. The dashboard uses clearly
labeled demonstration records unless an API base URL is configured.

## Project layout

- `backend/app/api`: FastAPI routing and versioned API entry points.
- `backend/app/core`: application configuration and shared infrastructure.
- `backend/app/db`: SQLAlchemy base and database session utilities.
- `backend/migrations`: Alembic schema migrations.
- `backend/app/models`: database model package.
- `backend/app/schemas`: Pydantic schema package.
- `backend/app/services`: business logic package.
- `backend/tests`: backend tests.
- `frontend/src`: React application, shared styles, and components.
- `frontend/src/data/demoDashboard.js`: isolated illustrative dashboard data.
- `frontend/src/services/dashboardApi.js`: API loading and response validation.
- `frontend/src/components/CaseManagement.jsx`: case list, details, and forms.
- `frontend/src/services/casesApi.js`: live Case API requests; no demo fallback.

## Development setup

1. Copy `.env.example` to the root `.env` and `backend/.env`. These are
   local-development credentials; change them before using sensitive data.
2. Start MySQL 8 and wait for its health check:

   ```powershell
   docker compose up -d --wait mysql
   ```

3. Install dependencies, apply migrations, and start the backend:

   ```powershell
   cd backend
   python -m pip install -e ".[dev]"
   python -m alembic upgrade head
   python -m uvicorn app.main:app --reload
   ```

4. In another terminal, install and start the frontend:

   ```powershell
   cd frontend
   npm install
   npm run dev
   ```

In addition to FastAPI's built-in documentation endpoints, the backend now
exposes the Cases API. Database access is lazy: the API can start without a
configured database, but case requests return an explicit service-unavailable
error until `DATABASE_URL` is configured and the migration has been applied.

## Case management

The Cases page uses live API data only; it never falls back to dashboard demo
records. The development Vite server proxies `/api` to `http://127.0.0.1:8000`.
For a deployed frontend, route `/api` to the backend on the same origin.

Available endpoints:

- `GET /health` — backend liveness.
- `GET /health/ready` — checks database readiness.
- `POST /api/v1/cases` — create a case.
- `GET /api/v1/cases` — list/search/filter cases with `q`, `status`, `severity`,
  `page`, and `size` (legacy `skip`/`limit` are also accepted).
- `GET /api/v1/cases/metrics` — total, open, critical, and resolved counts.
- `GET /api/v1/cases/{id}` — read case details and audit history. The path also
  accepts the generated case number.
- `PATCH /api/v1/cases/{id}` — edit case information and/or status.
- `DELETE /api/v1/cases/{id}` — soft-delete a case while retaining its audit history.

Case numbers are generated in the form `CT-YYYY-XXXXXXXX`. Existing records
are migrated to `CT-YYYY-NNNN`, and their previous assigned-investigator value
is retained as `assignedTo`. The audit actor is currently `system` because
authentication and investigator accounts are not implemented. Do not expose
this development API to untrusted networks until authentication and
authorization are implemented.

To verify a running backend, check `http://127.0.0.1:8000/health`, then
`http://127.0.0.1:8000/health/ready`; the second endpoint requires a configured
and reachable database. To run the backend tests, use `python -m pytest` from
`backend`. API tests use an isolated in-memory SQLite database; the Alembic
migrations also support SQLite tests, but deployment uses MySQL.

## Dashboard data source

The dashboard connects directly to `GET /api/v1/dashboard/overview` through the
`/api` proxy and displays live case totals, recent investigations, and recorded
audit activity from the configured database. Evidence integrity counts remain
honest (`0` items, no fabricated hashes) until the Evidence Repository module
is implemented.

To preview the dashboard with illustrative demonstration data instead of a live
backend, set `VITE_CYBERTRACE_DEMO_MODE=true` when starting the frontend.

The endpoint returns `metrics`, `cases`, `evidenceIntegrity`, `activityEvents`,
and `analytics` fields. Evidence verification records are expected to include
one current check per evidence item, with an `evidenceItemId`,
`comparisonPerformed`, `algorithm`, and `sha256Matches` field. A result is
counted as a verified SHA-256 match only when the check reports
`comparisonPerformed: true`, `algorithm: "SHA-256"`, and `sha256Matches: true`.

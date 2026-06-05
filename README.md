# Threat Intelligence Enrichment System

Threat Intelligence Enrichment System is a SOC-style platform that ingests security alerts, extracts indicators of compromise (IOCs), enriches them with threat intelligence, computes risk scores, and produces enriched alerts for downstream response and analysis.

**Repository:** [README.md](README.md)

## Tech Stack

- **Backend:** Python, FastAPI, Uvicorn
- **Data & Persistence:** PostgreSQL (SQLAlchemy), MongoDB (Motor)
- **Async & Messaging:** Celery workers, Redis, RabbitMQ
- **Auth & Security:** JWT, API keys, `python-jose`, `passlib`
- **Integrations:** PyMISP (MISP), OpenCTI client, HTTPX
- **Logging & Utils:** structlog, orjson, slowapi (rate limiting)
- **Frontend:** React + TypeScript, Vite, Tailwind CSS, React Router, @tanstack/react-query, Axios, Cytoscape
- **Containers / Dev:** Docker, docker-compose (Postgres, Mongo, Redis, RabbitMQ, MailHog, optional MISP/OpenCTI)
- **Testing:** pytest, pytest-asyncio

## Core Functionality

- REST API endpoints for alerts, IOCs, enrichment, enriched alerts, dashboard, auth, hunting and realtime (see `backend/app/api/`).
- Alert ingestion and IOC extraction via `indicator_extractor` service.
- Threat enrichment using MISP and OpenCTI connectors with demo fallback adapters.
- Risk scoring and reputation calculation attached to enriched alerts.
- Persistence in PostgreSQL (structured models) and MongoDB (enriched documents), with local JSON snapshots under `local-document-store/`.
- Background processing with Celery workers (connected to Redis/RabbitMQ) for async enrichment and tasks.
- Frontend provides dashboards, hunting interfaces, and graph visualizations (Cytoscape).
- WebSocket / realtime endpoints for live alert streams.

## Quick Start (Docker)

1. Copy environment template:

```powershell
cp .env.example .env
```

2. Build and start services:

```bash
docker compose up --build
```

3. Open services in your browser:

- Frontend: http://localhost:5173
- Backend docs (Swagger): http://localhost:8000/docs

4. (Optional) Seed demo data:

```powershell
docker compose exec backend python -m app.db.seed
```

## Local Development (non-Docker)

You can run services locally using the included scripts when Docker is unavailable. Example (Windows PowerShell):

```powershell
Set-Location "D:\8th SEMESTER\NCY_2\PROJECT"
.\run-local.ps1
```

This local mode uses embedded JSON storage and demo adapters where appropriate.

## Project Layout

- `backend/` — FastAPI application, DB models, services, integrations and workers
- `frontend/` — React + TypeScript UI built with Vite
- `docs/` — design docs, architecture and API guides
- `sample-data/` — demo alerts and IOC datasets
- `local-document-store/` — local JSON snapshots for quick inspection

## Configuration & Live Integrations

Set environment variables in `.env` to enable real TI platforms:

- `MISP_URL` / `MISP_API_KEY` / `MISP_LIVE_MODE`
- `OPENCTI_URL` / `OPENCTI_TOKEN` / `OPENCTI_LIVE_MODE`

When live mode flags are `false` the app falls back to bundled demo data and local adapters.

## Useful Commands

- Start everything with Docker Compose:

```bash
docker compose up --build
```

- Run frontend dev server:

```bash
cd frontend
npm install
npm run dev
```

- Run backend locally:

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Further Reading

- Architecture and API docs: see `docs/` directory.

---

If you want, I can also add a short Usage / Examples section, or commit this README to the repository for you. Would you like me to commit it now?

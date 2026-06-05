# Deployment Guide

## Local Deployment

1. Copy [`.env.example`](D:\8th SEMESTER\NCY_2\PROJECT\.env.example) to `.env`
2. Start the stack:

```powershell
docker compose up --build
```

3. Seed the database:

```powershell
docker compose exec backend python -m app.db.seed
```

## Services

- Backend API: `http://localhost:8000`
- Swagger docs: `http://localhost:8000/docs`
- Frontend: `http://localhost:5173`
- RabbitMQ management: `http://localhost:15672`
- MailHog: `http://localhost:8025`

## Real MISP/OpenCTI Integration

The project can run against real MISP and OpenCTI servers instead of the bundled demo data. Update `.env`:

```powershell
MISP_URL=https://your-misp.example.org
MISP_API_KEY=replace-with-real-misp-api-key
MISP_LIVE_MODE=true
OPENCTI_URL=https://your-opencti.example.org
OPENCTI_TOKEN=replace-with-real-opencti-token
OPENCTI_LIVE_MODE=true
```

Notes:

- MISP live search uses PyMISP first and falls back to the REST `restSearch` path.
- OpenCTI live enrichment uses the GraphQL API with bearer-token authentication.

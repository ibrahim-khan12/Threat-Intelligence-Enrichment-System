# Implementation Status

## Implemented In Local Mode

- IOC CRUD, tagging, search, sync, STIX import/export, and TAXII-style collection exposure
- Alert ingestion, IOC extraction, enrichment, correlation, scoring, MITRE mapping, and response recommendations
- Threat actor, malware, campaign, CVE, GeoIP, WHOIS/DNS, and reputation-style enrichment using local demo feeds
- JWT auth, RBAC, and API key authentication
- Sigma-style matching, YARA-style hash matching, heuristic AI classification, and anomaly scoring
- Threat hunting search and WebSocket event streaming
- Simulated Slack/Discord/email/SOAR delivery logs and response queue tracking

## Implemented As Production Live Integrations

- MISP live lookup and sync using PyMISP plus REST fallback when `MISP_LIVE_MODE=true`
- OpenCTI live GraphQL lookup path when `OPENCTI_LIVE_MODE=true`

## Still Dependent On External Services

- A reachable MISP server with a valid API key
- A reachable OpenCTI server with a valid API token
- Real Redis/Celery worker separation, RabbitMQ, MongoDB, and PostgreSQL runtime deployment
- Real webhook/email/SOAR integrations to outside systems
- Full machine-learning models beyond local heuristics

# API Guide

## Authentication

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/api-keys`
- `GET /api/auth/me`

Example login payload:

```json
{
  "username": "admin",
  "password": "admin123!"
}
```

## Alerts

- `POST /api/alerts`
- `GET /api/alerts`
- `GET /api/alerts/{id}`

Example alert:

```json
{
  "alert_id": "ALRT-1001",
  "source": "Suricata",
  "timestamp": "2026-05-08T10:00:00Z",
  "src_ip": "185.220.101.4",
  "domain": "malicious-login.com",
  "file_hash": "44d88612fea8a8f36de82e1278abb02f"
}
```

## IOC Management

- `POST /api/iocs`
- `GET /api/iocs`
- `PUT /api/iocs/{ioc_id}`
- `DELETE /api/iocs/{ioc_id}`
- `POST /api/iocs/sync/misp`
- `GET /api/iocs/export/stix`
- `POST /api/iocs/import/stix`
- `GET /api/iocs/taxii/collection`

## Enrichment

- `POST /api/enrich`
- `GET /api/enriched-alerts`
- `GET /api/enrich/enriched-alerts`
- `GET /api/enrich/ioc-relationships`
- `GET /api/enrich/threat-graph`

## Hunting

- `GET /api/hunting/search?q=APT29`
- `GET /api/hunting/search?mitre=T1105`
- `GET /api/hunting/search?severity=Critical`

## Dashboard

- `GET /api/dashboard/summary`
- `GET /api/dashboard/recent-enriched`
- `GET /api/dashboard/response-summary`

## Demo

- `POST /api/demo/run`
- `GET /api/demo/latest`

## Realtime

- `GET /ws/alerts`

## Cross-Module Integration

- `GET /api/integrations/module3/status`
- `POST /api/integrations/module3/import`

## Roles

- `admin`: Full IOC, alert, and sync control
- `analyst`: Alert ingestion, IOC management, and enrichment access
- `incident_responder`: Read-only access to alerts and enriched incident data

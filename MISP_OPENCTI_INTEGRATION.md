# Threat Intelligence Integration Guide

This guide provides MISP and OpenCTI API integration details for Module 4 (Threat Intelligence Enrichment).

## MISP Integration

### Configuration

Add these environment variables to `.env.local`:

```env
MISP_URL=http://your-misp-instance:80
MISP_API_KEY=your-misp-api-key
```

### API Endpoints Used

#### 1. Search Indicator
**Endpoint:** `POST /attributes/restSearch`

**Headers:**
```
Authorization: <MISP_API_KEY>
Accept: application/json
Content-Type: application/json
```

**Request:**
```bash
curl -X POST "http://your-misp-instance/attributes/restSearch" \
  -H "Authorization: your-misp-api-key" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"value": "185.220.101.4"}'
```

**Response:**
```json
{
  "response": {
    "Attribute": [
      {
        "type": "ip-src",
        "value": "185.220.101.4",
        "threat_level_id": "high",
        "event_id": 123,
        "Tag": [
          {"name": "malicious"},
          {"name": "tor"}
        ]
      }
    ]
  }
}
```

#### 2. Sync IOCs (Get Events)
**Endpoint:** `GET /events/index`

**Headers:**
```
Authorization: <MISP_API_KEY>
Accept: application/json
```

**Request:**
```bash
curl -X GET "http://your-misp-instance/events/index" \
  -H "Authorization: your-misp-api-key" \
  -H "Accept: application/json"
```

**Response:**
```json
[
  {
    "Event": {
      "id": 1,
      "Attribute": [
        {
          "type": "domain",
          "value": "malicious-domain.com",
          "threat_level_id": "high",
          "comment": "Phishing domain",
          "Tag": [
            {"name": "phishing"}
          ]
        }
      ]
    }
  }
]
```

### Supported IOC Types

- `ip-src` / `ip-dst` → Maps to `ip`
- `domain` → Maps to `domain`
- `url` → Maps to `url`
- `md5` → Maps to `md5`
- `sha256` → Maps to `sha256`

---

## OpenCTI Integration

### Configuration

Add these environment variables to `.env.local`:

```env
OPENCTI_URL=http://your-opencti-instance:8080
OPENCTI_TOKEN=your-opencti-api-token
```

### API Endpoint Used

#### Indicator Search (GraphQL)
**Endpoint:** `POST /graphql`

**Headers:**
```
Authorization: Bearer <OPENCTI_TOKEN>
Content-Type: application/json
```

**Request:**
```bash
curl -X POST "http://your-opencti-instance:8080/graphql" \
  -H "Authorization: Bearer your-opencti-api-token" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query IndicatorSearch($search: String!) { indicators(search: $search, first: 1) { edges { node { name ... on StixCyberObservable { objectLabel { value } } } } } }",
    "variables": {
      "search": "185.220.101.4"
    }
  }'
```

**GraphQL Query:**
```graphql
query IndicatorSearch($search: String!) {
  indicators(search: $search, first: 1) {
    edges {
      node {
        name
        ... on StixCyberObservable {
          objectLabel {
            value
          }
        }
      }
    }
  }
}
```

**Response:**
```json
{
  "data": {
    "indicators": {
      "edges": [
        {
          "node": {
            "name": "185.220.101.4",
            "objectLabel": [
              {"value": "CVE-2024-21412"},
              {"value": "APT29"}
            ]
          }
        }
      ]
    }
  }
}
```

### Data Extracted from OpenCTI

The integration extracts:
- **Threat Actor:** From object relationships
- **Malware Family:** From malware entities
- **Campaign:** From campaign relationships
- **MITRE ATT&CK Techniques:** From technique relationships
- **CVEs:** From CVE object labels

---

## Setup Instructions for Partner

### Step 1: Prepare Environment File
Create or update `backend/.env.local`:

```env
DEMO_MODE=false
MISP_URL=http://misp-server:80
MISP_API_KEY=xxxxxxxxxxxx
OPENCTI_URL=http://opencti-server:8080
OPENCTI_TOKEN=xxxxxxxxxxxx
DATABASE_URL=sqlite:///./local-threat-intel.db
MONGODB_URL=embedded://local
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=memory://
CELERY_RESULT_BACKEND=cache+memory://
JWT_SECRET=your-secret-key
DEMO_MODE=false
EMBEDDED_MODE=true
```

### Step 2: Validate Connectivity

Test MISP:
```bash
curl -X POST "http://your-misp-instance/attributes/restSearch" \
  -H "Authorization: your-misp-api-key" \
  -H "Content-Type: application/json" \
  -d '{"value": "1.2.3.4"}'
```

Test OpenCTI:
```bash
curl -X POST "http://your-opencti-instance:8080/graphql" \
  -H "Authorization: Bearer your-opencti-api-token" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
```

### Step 3: Start Backend

```bash
cd backend
python -m app.db.seed
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Step 4: Start Frontend

```bash
cd frontend
npm run dev -- --host 0.0.0.0 --port 5173
```

---

## Testing the Integration

### 1. Login
```bash
curl -X POST "http://localhost:8000/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123!"}'
```

### 2. Test MISP Sync
```bash
curl -X POST "http://localhost:8000/api/iocs/sync/misp" \
  -H "Authorization: Bearer <token>"
```

### 3. Test Enrichment
```bash
curl -X POST "http://localhost:8000/api/enrich" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "TEST-001",
    "source": "Test",
    "timestamp": "2026-05-10T10:00:00Z",
    "src_ip": "185.220.101.4",
    "domain": "malicious-domain.com"
  }'
```

---

## Troubleshooting

### Connection Errors
- Verify `MISP_URL` and `OPENCTI_URL` are correct
- Check firewall rules allow access from backend host
- Confirm API keys/tokens are valid

### No Results Returned
- Ensure the IOC exists in MISP/OpenCTI
- Check that IOC type is supported
- Verify API credentials have read permissions

### Module Error
Check backend logs:
```bash
tail -f local-document-store/audit_logs.json
```

---

## API Rate Limits & Timeouts

- **Connection Timeout:** 5 seconds per request
- **Max Results:** 25 events from MISP /events/index
- **Recommended:** Rate limit MISP calls to avoid server overload

---

## Support

For issues or questions about this integration:
1. Check the backend logs: `tail -f local-document-store/*.json`
2. Verify endpoint connectivity with curl commands above
3. Confirm environment variables are loaded: `echo $MISP_URL`

# Quick Setup Reference for Partner

## Copy-Paste Configuration

### 1. Environment Variables (.env.local)
```ini
# Production Mode with Real Threat Intelligence
DEMO_MODE=false
EMBEDDED_MODE=true

# MISP Configuration
MISP_URL=https://your-misp.example.org
MISP_API_KEY=your_misp_api_key_here
MISP_LIVE_MODE=true
MISP_VERIFY_SSL=false
MISP_TIMEOUT_SECONDS=10

# OpenCTI Configuration  
OPENCTI_URL=https://your-opencti.example.org
OPENCTI_TOKEN=your_opencti_api_token_here
OPENCTI_LIVE_MODE=true
OPENCTI_VERIFY_SSL=false
OPENCTI_TIMEOUT_SECONDS=10

# Database (local mode)
DATABASE_URL=sqlite:///./local-threat-intel.db
MONGODB_URL=embedded://local
REDIS_URL=redis://localhost:6379/0

# Celery (local mode)
CELERY_BROKER_URL=memory://
CELERY_RESULT_BACKEND=cache+memory://

# Security
JWT_SECRET=change-this-to-random-string-in-production
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# API Settings
API_RATE_LIMIT_PER_MINUTE=120
API_PREFIX=/api

# Integrations (Demo/Fallback)
ABUSEIPDB_API_KEY=demo
VIRUSTOTAL_API_KEY=demo

# Notifications (Optional)
SLACK_WEBHOOK_URL=
DISCORD_WEBHOOK_URL=

# Email (Local Testing)
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_FROM=soc@example.local

# Logging
LOG_LEVEL=INFO

# Frontend
FRONTEND_API_URL=http://localhost:8000/api
```

### 2. Test MISP Connection
```bash
# Replace with your values
MISP_URL="http://your-misp-host:80"
API_KEY="your-misp-api-key"

# Test search
curl -X POST "$MISP_URL/attributes/restSearch" \
  -H "Authorization: $API_KEY" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"value": "8.8.8.8"}'
```

### 3. Test OpenCTI Connection
```bash
# Replace with your values
OPENCTI_URL="http://your-opencti-host:8080"
API_TOKEN="your-opencti-api-token"

# Test GraphQL
curl -X POST "$OPENCTI_URL/graphql" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
```

### 4. Start Backend (Production)
```bash
cd backend

# Create/update env file with values above
nano .env.local  # or use your editor

# Seed database
python -m app.db.seed

# Start API server
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 5. Start Frontend
```bash
cd frontend

# Install dependencies (if needed)
npm install

# Start dev server
npm run dev -- --host 0.0.0.0 --port 5173
```

## Test Endpoints

### Login
```bash
curl -X POST "http://localhost:8000/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123!"}'
```

### Sync IOCs from MISP
```bash
TOKEN="your-jwt-token-from-login"

curl -X POST "http://localhost:8000/api/iocs/sync/misp" \
  -H "Authorization: Bearer $TOKEN"
```

### Test Enrichment
```bash
TOKEN="your-jwt-token-from-login"

curl -X POST "http://localhost:8000/api/enrich" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "TEST-ALERT-001",
    "source": "TestSensor",
    "timestamp": "2026-05-10T10:00:00Z",
    "src_ip": "8.8.8.8",
    "domain": "example.com",
    "file_hash": "44d88612fea8a8f36de82e1278abb02f"
  }'
```

### Get Enriched Alerts
```bash
TOKEN="your-jwt-token-from-login"

curl -X GET "http://localhost:8000/api/enriched-alerts" \
  -H "Authorization: Bearer $TOKEN"
```

## Module Integration Points

### Input (from Upstream Modules)
- **Alert Ingestion:** `POST /api/alerts`
  - Source: Alert Detection Module
  - Contains: alert_id, source, timestamp, raw payload with IPs/domains/hashes

### Processing
- **IOC Extraction:** Automatic from alert payloads
- **MISP Lookup:** `search_indicator()` → threat level, tags, event ID
- **OpenCTI Lookup:** `lookup_indicator()` → threat actor, malware, campaign, MITRE ATT&CK, CVEs
- **Risk Scoring:** Combined threat level calculation
- **Alert Enrichment:** Stores in MongoDB (embedded mode)

### Output (to Downstream Modules)
- **Incident Response:** `POST /api/incidents`
  - Enriched alert data
  - Risk score and severity
  - Recommended actions
  - IOC relationships

---

## Credentials Needed

| Service | Variable | Example | Source |
|---------|----------|---------|--------|
| MISP | `MISP_API_KEY` | `abc123def456...` | MISP Admin → My Account |
| OpenCTI | `OPENCTI_TOKEN` | `xyz789uvw012...` | OpenCTI Admin → Settings → API Keys |

---

## Supported IOC Types

**MISP Types:**
- IP: `ip-src`, `ip-dst` 
- Domain: `domain`
- URL: `url`
- File Hash: `md5`, `sha256`

**OpenCTI Types:**
- Query any indicator value
- Returns threat context and relationships

---

## Debug Commands

### Check Logs
```bash
# Backend logs
tail -f backend/local-document-store/audit_logs.json

# Enriched alerts
tail -f backend/local-document-store/enriched_alerts.json

# Incident queue
tail -f backend/local-document-store/incident_queue.json
```

### List Synced IOCs
```bash
sqlite3 backend/local-threat-intel.db "SELECT * FROM ioc LIMIT 10;"
```

### Check Backend Health
```bash
curl http://localhost:8000/health
```

# Enrichment Engine

The enrichment engine coordinates:

- IOC extraction
- MISP and OpenCTI lookups
- reputation, WHOIS, DNS, and GeoIP context
- risk scoring
- incident response forwarding

Implementation entry points:

- [backend/app/services/indicator_extractor.py](D:\8th SEMESTER\NCY_2\PROJECT\backend\app\services\indicator_extractor.py)
- [backend/app/services/enrichment.py](D:\8th SEMESTER\NCY_2\PROJECT\backend\app\services\enrichment.py)
- [backend/app/services/scoring.py](D:\8th SEMESTER\NCY_2\PROJECT\backend\app\services\scoring.py)


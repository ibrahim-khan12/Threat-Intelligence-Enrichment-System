# OpenCTI Integration

This directory documents the OpenCTI connector boundary. The current backend uses a mock-first adapter in [backend/app/integrations/opencti_client.py](D:\8th SEMESTER\NCY_2\PROJECT\backend\app\integrations\opencti_client.py) that simulates:

- indicator lookups
- MITRE ATT&CK mappings
- actor, campaign, and malware relationships

For live OpenCTI usage, replace the adapter with GraphQL requests authenticated by `OPENCTI_TOKEN`.


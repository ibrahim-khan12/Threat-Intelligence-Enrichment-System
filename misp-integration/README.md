# MISP Integration

This directory documents the MISP connector boundary. The running backend currently uses a mock-first `MISPClient` that can:

- search indicator attributes
- sync IOC fixtures
- simulate event correlation

To integrate with live MISP, replace the adapter in [backend/app/integrations/misp_client.py](D:\8th SEMESTER\NCY_2\PROJECT\backend\app\integrations\misp_client.py) with `PyMISP` calls using `MISP_URL` and `MISP_API_KEY`.


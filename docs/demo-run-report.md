# Demo Run Report

Run timestamp: 2026-05-08 23:08:57

## Environment

- Backend health: ok
- Frontend URL: http://127.0.0.1:5173
- API docs URL: http://127.0.0.1:8000/docs

## IOC Management

- Created IOC id: 7
- IOC value: https://ransom-note-20260508230854.example/dropper
- Updated threat level: critical
- Search result count for custom IOC: 1
- MISP sync result count: 4

## Alert Ingestion

- Ingested alert id: ALRT-DEMO-20260508230854
- Alert source: Suricata
- Extracted IOC count: 6

## Enrichment Result

- Enriched alert id: ALRT-DEMO-20260508230854
- Risk score: 100
- Severity: Critical
- Recommended action: Block IP, isolate endpoint, and open incident ticket
- MITRE ATT&CK techniques: T1059, T1105, T1189, T1204, T1486, T1566

### IOC Matches
- 185.220.101.4 | APT29 | Emotet | Malicious | Russia
- malicious-login.com | Scattered Spider | EvilProxy | Malicious | Netherlands
- https://ransom-note-20260508230854.example/dropper |  |  | Unknown | Unknown
- 44d88612fea8a8f36de82e1278abb02f | Wizard Spider | TrickBot | Malicious | Germany

## Correlation and Graph

- Relationship rows for demo alert: 4
- Threat graph node count: 15
- Threat graph edge count: 27

## Dashboard Snapshot

- Total alerts: 6
- Enriched alerts: 3
- Critical alerts: 3
- Known IOCs: 7

## Incident Response Simulation

- Incident queue entries for demo alert: 1
- Audit log entries for demo alert: 1

## Cleanup Note

The custom IOC created for the walkthrough is still present in the database so it remains visible in the dashboard and search views.

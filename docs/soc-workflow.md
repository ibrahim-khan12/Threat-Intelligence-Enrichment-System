# SOC Workflow Explanation

## Incident Lifecycle

1. Sensors send alerts to the backend API.
2. Backend parses alert fields and extracts IOCs.
3. Indicators are checked against:
   - local IOC registry
   - MISP event attributes
   - OpenCTI relationships
   - simulated AbuseIPDB / VirusTotal style reputation data
4. Correlation engine assigns:
   - threat actor
   - malware family
   - campaign
   - CVEs
   - MITRE ATT&CK techniques
   - GeoIP and WHOIS context
5. Risk scoring produces a severity label.
6. Enriched data is written to MongoDB and queued for response action.
7. Dashboard surfaces real-time analyst context and graph relationships.


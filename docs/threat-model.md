# Threat Model

## Assets

- IOC registry and enrichment results
- SOC alerts and incident queue data
- User accounts, JWT secrets, and API credentials
- Integration credentials for MISP, OpenCTI, webhooks, and email

## Threats

- Unauthorized API access to alert or IOC data
- IOC poisoning through malicious feed input
- Replay or flood attacks against alert ingestion endpoints
- Leakage of enrichment results to untrusted third parties
- Credential exposure in container logs or environment variables

## Mitigations

- JWT-based authentication and RBAC
- Role-guarded routes for sensitive actions
- Rate limiting support through `slowapi`
- Structured audit trails in MongoDB
- Environment-based secret injection
- Separation of structured relational data and document enrichment data

## Residual Risks

- Demo adapters are still used unless `MISP_LIVE_MODE=true` and `OPENCTI_LIVE_MODE=true` are configured with reachable services
- Email/webhook delivery is simulated by default

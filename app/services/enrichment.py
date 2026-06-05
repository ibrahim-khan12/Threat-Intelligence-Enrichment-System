from datetime import datetime, timezone

from fastapi.encoders import jsonable_encoder
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.mongo import mongo_db
from app.integrations.demo_data import IOC_FIXTURES
from app.integrations.misp_client import MISPClient
from app.integrations.opencti_client import OpenCTIClient
from app.integrations.reputation import lookup_reputation
from app.models.ioc import IOC
from app.services.detections import anomaly_score, classify_alert, run_sigma_matches, run_yara_matches
from app.services.indicator_extractor import extract_iocs
from app.services.realtime import event_manager
from app.services.scoring import calculate_risk_score, recommended_action


class EnrichmentService:
    def __init__(self) -> None:
        self.misp = MISPClient()
        self.opencti = OpenCTIClient()

    async def enrich_alert(self, alert_payload: dict, db: Session | None = None) -> dict:
        indicators = extract_iocs(alert_payload)
        matches: list[dict] = []

        for ioc in indicators:
            value = ioc["value"]
            local_record = None
            if db is not None:
                local_record = db.execute(select(IOC).where(IOC.value == value)).scalar_one_or_none()
            misp = self.misp.search_indicator(value) or {}
            opencti = self.opencti.lookup_indicator(value) or {}
            reputation = lookup_reputation(value)

            opencti_labels = opencti.get("labels", [])
            merged_tags = list(
                dict.fromkeys(
                    (getattr(local_record, "tags", None) or misp.get("tags", [])) + opencti_labels
                )
            )
            if local_record or misp or opencti or reputation["reputation"] != "Unknown":
                matches.append(
                    {
                        "indicator": value,
                        "ioc_type": ioc["ioc_type"],
                        "source": getattr(local_record, "source", None) or misp.get("source", "demo"),
                        "threat_level": getattr(local_record, "threat_level", None) or misp.get("threat_level", "medium"),
                        "tags": merged_tags,
                        "threat_actor": opencti.get("threat_actor"),
                        "malware_family": opencti.get("malware_family"),
                        "campaign": opencti.get("campaign"),
                        "mitre_attack": opencti.get("mitre_attack", []),
                        "cves": opencti.get("cves", []),
                        "reputation": reputation["reputation"],
                        "country": reputation["country"],
                        "whois": reputation["whois"],
                        "dns": reputation["dns"],
                        "geo": reputation["geo"],
                    }
                )

        risk_score, severity = calculate_risk_score(matches)
        sigma_matches = run_sigma_matches(alert_payload)
        yara_matches = run_yara_matches(alert_payload)
        ai_summary = classify_alert(alert_payload, matches)
        anomaly = anomaly_score(alert_payload, matches)
        enriched = {
            "alert_id": alert_payload["alert_id"],
            "source": alert_payload["source"],
            "created_at": datetime.now(timezone.utc),
            "raw_alert": jsonable_encoder(alert_payload),
            "risk_score": risk_score,
            "severity": severity,
            "ioc_matches": matches,
            "mitre_attack": sorted({tech for match in matches for tech in match.get("mitre_attack", [])}),
            "recommended_action": recommended_action(severity),
            "sigma_matches": sigma_matches,
            "yara_matches": yara_matches,
            "ai_classification": ai_summary,
            "anomaly_score": anomaly,
            "threat_hunt_terms": self._hunt_terms(matches),
        }

        await mongo_db.enriched_alerts.update_one(
            {"alert_id": enriched["alert_id"]},
            {"$set": jsonable_encoder(enriched)},
            upsert=True,
        )
        await mongo_db.audit_logs.insert_one(
            jsonable_encoder(
                {
                    "event": "alert_enriched",
                    "alert_id": enriched["alert_id"],
                    "severity": severity,
                    "created_at": datetime.now(timezone.utc),
                }
            )
        )
        await event_manager.broadcast(
            {
                "event": "enriched_alert",
                "alert_id": enriched["alert_id"],
                "severity": severity,
                "risk_score": risk_score,
                "recommended_action": enriched["recommended_action"],
            }
        )
        return enriched

    def _hunt_terms(self, matches: list[dict]) -> list[str]:
        terms = set()
        for match in matches:
            for field in ("indicator", "threat_actor", "malware_family", "campaign", "country"):
                value = match.get(field)
                if value:
                    terms.add(str(value))
            for technique in match.get("mitre_attack", []):
                terms.add(technique)
        return sorted(terms)

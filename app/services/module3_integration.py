import json
from pathlib import Path
import re

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.alert import Alert
from app.services.enrichment import EnrichmentService
from app.services.notifications import forward_incident

HASH32 = re.compile(r"^[a-fA-F0-9]{32}$")
HASH64 = re.compile(r"^[a-fA-F0-9]{64}$")
IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


class Module3IntegrationService:
    def __init__(self) -> None:
        self.source_path = Path(settings.module3_generated_alerts_path).resolve()
        self.handoff_path = Path(settings.module4_ir_handoff_path).resolve()
        self.enrichment_service = EnrichmentService()

    def status(self) -> dict:
        return {
            "source_path": str(self.source_path),
            "handoff_path": str(self.handoff_path),
            "source_exists": self.source_path.exists(),
            "handoff_exists": self.handoff_path.exists(),
        }

    async def import_and_forward(self, db: Session) -> dict:
        if not self.source_path.exists():
            raise FileNotFoundError(f"Module 3 alert file not found: {self.source_path}")

        imported = 0
        skipped = 0
        handoff_records: list[dict] = []

        for line in self.source_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if "Module 4 - Threat Intelligence Enrichment" not in str(record.get("destination_module", "")):
                skipped += 1
                continue

            alert_id = record["alert_id"]
            existing = db.query(Alert).filter(Alert.alert_id == alert_id).first()
            if existing:
                skipped += 1
                continue

            payload = self._map_module3_alert(record)
            alert = Alert(
                alert_id=payload["alert_id"],
                source=payload["source"],
                timestamp=self._timestamp(payload["@timestamp"]),
                severity=record.get("severity", "Low").title(),
                status="imported-from-module3",
                raw_payload=payload,
                extracted_iocs=[],
                summary=record.get("summary"),
            )
            db.add(alert)
            db.commit()

            enriched = await self.enrichment_service.enrich_alert(payload, db)
            await forward_incident(enriched)
            handoff_records.append(self._build_ir_handoff(record, enriched))
            imported += 1

        written = self._write_handoff(handoff_records)
        return {
            "imported_alerts": imported,
            "skipped_alerts": skipped,
            "handoff_records_written": written,
            "handoff_path": str(self.handoff_path),
        }

    def _map_module3_alert(self, record: dict) -> dict:
        payload = {
            "alert_id": record["alert_id"],
            "source": "Module 3 - SIEM and Visualization Layer",
            "@timestamp": record.get("@timestamp"),
            "timestamp": record.get("@timestamp"),
            "src_ip": record.get("src_ip"),
            "dest_ip": record.get("dest_ip"),
            "domain": None,
            "url": None,
            "file_hash": None,
            "payload": {
                "rule_name": record.get("rule_name"),
                "severity": record.get("severity"),
                "risk_score": record.get("risk_score"),
                "host": record.get("host"),
                "user": record.get("user"),
                "summary": record.get("summary"),
                "mitre": record.get("mitre", []),
                "evidence_event_ids": record.get("evidence_event_ids", []),
                "upstream_source": record.get("source"),
            },
        }
        ioc = record.get("ioc")
        if isinstance(ioc, str):
            if HASH32.match(ioc) or HASH64.match(ioc):
                payload["file_hash"] = ioc
            elif IPV4.match(ioc):
                payload["dest_ip"] = ioc
            elif ioc.startswith("http://") or ioc.startswith("https://"):
                payload["url"] = ioc
            elif DOMAIN.match(ioc):
                payload["domain"] = ioc
            payload["payload"]["ioc"] = ioc
        return payload

    def _build_ir_handoff(self, module3_record: dict, enriched: dict) -> dict:
        return {
            "source_module": "Module 4 - Threat Intelligence Enrichment",
            "upstream_module": "Module 3 - SIEM and Visualization Layer",
            "downstream_module": "Module 5 - Incident Response and Automation",
            "alert_id": enriched["alert_id"],
            "timestamp": enriched["created_at"],
            "original_rule_name": module3_record.get("rule_name"),
            "severity": enriched["severity"],
            "risk_score": enriched["risk_score"],
            "recommended_action": enriched["recommended_action"],
            "mitre_attack": enriched.get("mitre_attack", []),
            "ioc_matches": enriched.get("ioc_matches", []),
            "ai_classification": enriched.get("ai_classification", {}),
            "anomaly_score": enriched.get("anomaly_score"),
            "summary": module3_record.get("summary"),
        }

    def _write_handoff(self, records: list[dict]) -> int:
        self.handoff_path.parent.mkdir(parents=True, exist_ok=True)
        with self.handoff_path.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, default=str) + "\n")
        return len(records)

    @staticmethod
    def _timestamp(value: str | None):
        from datetime import datetime

        if not value:
            return datetime.utcnow()
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

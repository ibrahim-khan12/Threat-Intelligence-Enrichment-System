from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.encoders import jsonable_encoder
from sqlalchemy.orm import Session

from app.api.deps import require_roles
from app.db.mongo import mongo_db
from app.db.postgres import get_db
from app.integrations.misp_client import MISPClient
from app.models.alert import Alert
from app.models.ioc import IOC
from app.models.user import User
from app.schemas.demo import DemoRunResponse
from app.services.enrichment import EnrichmentService
from app.services.indicator_extractor import extract_iocs
from app.services.notifications import forward_incident

router = APIRouter(prefix="/demo", tags=["demo"])


@router.post("/run", response_model=DemoRunResponse)
async def run_demo(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    custom_url = f"https://ransom-note-{run_id}.example/dropper"

    ioc = IOC(
        ioc_type="url",
        value=custom_url,
        threat_level="critical",
        source="manual-demo",
        tags=["ransomware", "payload", "demo", "escalated"],
        description="IOC created by one-click dashboard demo run",
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)

    for item in MISPClient().sync_iocs():
        existing = db.query(IOC).filter(IOC.value == item["value"]).first()
        if not existing:
            db.add(
                IOC(
                    ioc_type=item["ioc_type"],
                    value=item["value"],
                    threat_level=item["threat_level"],
                    source=item["source"],
                    tags=item["tags"],
                    description=item.get("description"),
                )
            )
    db.commit()

    payload = {
        "alert_id": f"ALRT-DEMO-{run_id}",
        "source": "Suricata",
        "timestamp": datetime(2026, 5, 8, 10, 45, tzinfo=timezone.utc).isoformat(),
        "src_ip": "185.220.101.4",
        "dest_ip": "10.0.5.24",
        "domain": "malicious-login.com",
        "url": custom_url,
        "file_hash": "44d88612fea8a8f36de82e1278abb02f",
        "payload": {
            "signature": "ET TROJAN Demo multi-indicator alert",
            "sensor": "soc-lab-suricata-01",
            "note": "Simulated phishing plus malware delivery alert",
        },
    }
    encoded_payload = jsonable_encoder(payload)
    if db.query(Alert).filter(Alert.alert_id == encoded_payload["alert_id"]).first():
        raise HTTPException(status_code=409, detail="Demo alert already exists")

    alert = Alert(
        alert_id=encoded_payload["alert_id"],
        source=encoded_payload["source"],
        timestamp=datetime.fromisoformat(encoded_payload["timestamp"]),
        raw_payload=encoded_payload,
        extracted_iocs=extract_iocs(encoded_payload),
        summary=f"{encoded_payload['source']} demo alert with {len(extract_iocs(encoded_payload))} extracted indicators",
    )
    db.add(alert)
    db.commit()

    service = EnrichmentService()
    enriched = await service.enrich_alert(encoded_payload, db)
    await forward_incident(enriched)

    return DemoRunResponse(
        alert_id=enriched["alert_id"],
        created_ioc_id=ioc.id,
        risk_score=enriched["risk_score"],
        severity=enriched["severity"],
        recommended_action=enriched["recommended_action"],
    )


@router.get("/latest")
async def latest_demo_status(
    _: User = Depends(require_roles("admin", "analyst", "incident_responder")),
):
    cursor = mongo_db.enriched_alerts.find({}, {"_id": 0}).sort("created_at", -1).limit(1)
    latest = None
    async for item in cursor:
        latest = item
        break
    if not latest:
        return {"latest": None}

    top_match = latest["ioc_matches"][0] if latest.get("ioc_matches") else {}
    return {
        "latest": {
            "alert_id": latest["alert_id"],
            "severity": latest["severity"],
            "risk_score": latest["risk_score"],
            "recommended_action": latest["recommended_action"],
            "threat_actor": top_match.get("threat_actor"),
            "malware_family": top_match.get("malware_family"),
            "indicator": top_match.get("indicator"),
            "ai_classification": latest.get("ai_classification", {}),
            "sigma_matches": latest.get("sigma_matches", []),
            "yara_matches": latest.get("yara_matches", []),
        }
    }

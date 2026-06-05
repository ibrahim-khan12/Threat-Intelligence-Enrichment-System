from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import require_roles
from app.db.mongo import mongo_db
from app.db.postgres import get_db
from app.models.alert import Alert
from app.models.ioc import IOC
from app.models.user import User

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
async def summary(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst", "incident_responder")),
):
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    total_iocs = db.query(func.count(IOC.id)).scalar() or 0
    enriched = await mongo_db.enriched_alerts.count_documents({})
    critical = await mongo_db.enriched_alerts.count_documents({"severity": "Critical"})
    by_source = [
        {"source": source, "count": count}
        for source, count in db.query(Alert.source, func.count(Alert.id)).group_by(Alert.source).all()
    ]
    return {
        "total_alerts": total_alerts,
        "total_iocs": total_iocs,
        "enriched_alerts": enriched,
        "critical_alerts": critical,
        "alerts_by_source": by_source,
    }


@router.get("/recent-enriched")
async def recent_enriched(
    _: User = Depends(require_roles("admin", "analyst", "incident_responder")),
):
    cursor = mongo_db.enriched_alerts.find({}, {"_id": 0}).sort("created_at", -1)
    items = [item async for item in cursor]
    recent = []
    for item in items[:8]:
        lead = item["ioc_matches"][0] if item.get("ioc_matches") else {}
        recent.append(
            {
                "alert_id": item["alert_id"],
                "source": item["source"],
                "severity": item["severity"],
                "risk_score": item["risk_score"],
                "threat_actor": lead.get("threat_actor"),
                "malware_family": lead.get("malware_family"),
                "recommended_action": item["recommended_action"],
                "created_at": item["created_at"],
            }
        )
    return recent


@router.get("/response-summary")
async def response_summary(
    _: User = Depends(require_roles("admin", "analyst", "incident_responder")),
):
    notifications = await mongo_db.notification_logs.count_documents({})
    soar = await mongo_db.soar_actions.count_documents({})
    queued = await mongo_db.incident_queue.count_documents({})
    return {
        "notifications": notifications,
        "soar_actions": soar,
        "incident_queue": queued,
    }

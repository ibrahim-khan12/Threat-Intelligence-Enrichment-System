from fastapi import APIRouter, Depends

from app.api.deps import require_roles
from app.db.mongo import mongo_db

router = APIRouter(prefix="/hunting", tags=["hunting"])


@router.get("/search")
async def hunt(
    q: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    mitre: str | None = None,
    _: object = Depends(require_roles("admin", "analyst", "incident_responder")),
):
    cursor = mongo_db.enriched_alerts.find({}, {"_id": 0}).sort("created_at", -1)
    results = []
    async for item in cursor:
        if severity and item.get("severity") != severity:
            continue
        if source and item.get("source") != source:
            continue
        if mitre and mitre not in item.get("mitre_attack", []):
            continue
        if q:
            haystack = " ".join(item.get("threat_hunt_terms", [])) + " " + item.get("alert_id", "")
            if q.lower() not in haystack.lower():
                continue
        results.append(item)
    return results

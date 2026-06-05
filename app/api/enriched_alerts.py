from fastapi import APIRouter, Depends

from app.api.deps import require_roles
from app.db.mongo import mongo_db

router = APIRouter(prefix="/enriched-alerts", tags=["enriched-alerts"])


@router.get("")
async def list_enriched_alerts(
    _: object = Depends(require_roles("admin", "analyst", "incident_responder")),
):
    cursor = mongo_db.enriched_alerts.find({}, {"_id": 0}).sort("created_at", -1)
    return [item async for item in cursor]

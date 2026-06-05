from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import require_roles
from app.db.mongo import mongo_db
from app.db.postgres import get_db
from app.models.user import User
from app.schemas.alert import AlertIn
from app.services.enrichment import EnrichmentService

router = APIRouter(prefix="/enrich", tags=["enrichment"])


@router.post("")
async def enrich_now(
    payload: AlertIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    service = EnrichmentService()
    return await service.enrich_alert(payload.model_dump(), db)


@router.get("/enriched-alerts")
async def list_enriched_alerts(
    _: User = Depends(require_roles("admin", "analyst", "incident_responder")),
):
    cursor = mongo_db.enriched_alerts.find({}, {"_id": 0}).sort("created_at", -1)
    return [item async for item in cursor]


@router.get("/ioc-relationships")
async def ioc_relationships(
    _: User = Depends(require_roles("admin", "analyst", "incident_responder")),
):
    cursor = mongo_db.enriched_alerts.find({}, {"_id": 0, "ioc_matches": 1, "alert_id": 1})
    relationships = []
    async for doc in cursor:
        for match in doc["ioc_matches"]:
            relationships.append(
                {
                    "alert_id": doc["alert_id"],
                    "indicator": match["indicator"],
                    "threat_actor": match.get("threat_actor"),
                    "campaign": match.get("campaign"),
                    "malware_family": match.get("malware_family"),
                    "mitre_attack": match.get("mitre_attack", []),
                }
            )
    return relationships


@router.get("/threat-graph")
async def threat_graph(
    _: User = Depends(require_roles("admin", "analyst", "incident_responder")),
):
    cursor = mongo_db.enriched_alerts.find({}, {"_id": 0, "ioc_matches": 1})
    nodes = {}
    edges = []
    async for doc in cursor:
        for match in doc["ioc_matches"]:
            indicator = match["indicator"]
            nodes[indicator] = {"id": indicator, "label": indicator, "type": "indicator"}
            for key in ("threat_actor", "malware_family", "campaign"):
                value = match.get(key)
                if value:
                    nodes[value] = {"id": value, "label": value, "type": key}
                    edges.append({"source": indicator, "target": value})
    return {"nodes": list(nodes.values()), "edges": edges}

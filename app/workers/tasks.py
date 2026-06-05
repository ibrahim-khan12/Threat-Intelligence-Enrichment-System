import asyncio

from app.db.postgres import SessionLocal
from app.services.enrichment import EnrichmentService
from app.services.notifications import forward_incident
from app.workers.celery_app import celery_app


@celery_app.task(name="enrich_alert_task")
def enrich_alert_task(alert_payload: dict):
    async def runner():
        db = SessionLocal()
        try:
            service = EnrichmentService()
            enriched = await service.enrich_alert(alert_payload, db)
            await forward_incident(enriched)
            return enriched
        finally:
            db.close()

    return asyncio.run(runner())


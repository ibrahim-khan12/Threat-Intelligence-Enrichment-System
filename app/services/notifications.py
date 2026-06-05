from datetime import datetime, timezone

from fastapi.encoders import jsonable_encoder

from app.db.mongo import mongo_db


async def forward_incident(enriched_alert: dict) -> None:
    await mongo_db.incident_queue.insert_one(
        jsonable_encoder(
            {
            "alert_id": enriched_alert["alert_id"],
            "status": "queued",
            "recommended_action": enriched_alert["recommended_action"],
            "severity": enriched_alert["severity"],
            "created_at": datetime.now(timezone.utc),
            }
        )
    )
    await mongo_db.notification_logs.insert_one(
        jsonable_encoder(
            {
                "alert_id": enriched_alert["alert_id"],
                "channels": ["slack", "discord", "email", "soar"],
                "status": "simulated-delivery",
                "created_at": datetime.now(timezone.utc),
            }
        )
    )
    await mongo_db.soar_actions.insert_one(
        jsonable_encoder(
            {
                "alert_id": enriched_alert["alert_id"],
                "playbook": "block-ip-isolate-host-create-ticket",
                "actions": [
                    "block malicious IP",
                    "quarantine host",
                    "create incident ticket",
                    "generate analyst report",
                ],
                "status": "simulated",
                "created_at": datetime.now(timezone.utc),
            }
        )
    )

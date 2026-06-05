from fastapi import APIRouter, Depends, HTTPException
from fastapi.encoders import jsonable_encoder
from sqlalchemy.orm import Session

from app.api.deps import require_roles
from app.db.postgres import get_db
from app.models.alert import Alert
from app.models.user import User
from app.schemas.alert import AlertIn, AlertRead
from app.services.indicator_extractor import extract_iocs
from app.workers.tasks import enrich_alert_task

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.post("", response_model=AlertRead)
def ingest_alert(
    payload: AlertIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    existing = db.query(Alert).filter(Alert.alert_id == payload.alert_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Alert already exists")
    raw_payload = jsonable_encoder(payload.model_dump())
    extracted = extract_iocs(raw_payload)
    alert = Alert(
        alert_id=payload.alert_id,
        source=payload.source,
        timestamp=payload.timestamp,
        raw_payload=raw_payload,
        extracted_iocs=extracted,
        summary=f"{payload.source} alert with {len(extracted)} extracted indicators",
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    enrich_alert_task.delay(raw_payload)
    return alert


@router.get("", response_model=list[AlertRead])
def list_alerts(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst", "incident_responder")),
):
    return db.query(Alert).order_by(Alert.timestamp.desc()).all()


@router.get("/{alert_id}", response_model=AlertRead)
def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst", "incident_responder")),
):
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

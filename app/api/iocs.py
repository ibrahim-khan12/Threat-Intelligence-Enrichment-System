from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import require_roles
from app.db.postgres import get_db
from app.integrations.misp_client import MISPClient
from app.models.ioc import IOC
from app.models.user import User
from app.schemas.ioc import IOCCreate, IOCRead, IOCUpdate
from app.services.stix import export_iocs_to_stix, import_iocs_from_stix

router = APIRouter(prefix="/iocs", tags=["iocs"])


@router.post("", response_model=IOCRead)
def create_ioc(
    payload: IOCCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    existing = db.query(IOC).filter(IOC.value == payload.value).first()
    if existing:
        raise HTTPException(status_code=400, detail="IOC already exists")
    ioc = IOC(**payload.model_dump())
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return ioc


@router.get("", response_model=list[IOCRead])
def list_iocs(
    search: str | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst", "incident_responder")),
):
    query = db.query(IOC)
    if search:
        query = query.filter(IOC.value.ilike(f"%{search}%"))
    return query.order_by(IOC.last_seen.desc()).all()


@router.put("/{ioc_id}", response_model=IOCRead)
def update_ioc(
    ioc_id: int,
    payload: IOCUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(ioc, field, value)
    db.commit()
    db.refresh(ioc)
    return ioc


@router.delete("/{ioc_id}")
def delete_ioc(
    ioc_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin")),
):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    db.delete(ioc)
    db.commit()
    return {"deleted": True}


@router.post("/sync/misp", response_model=list[IOCRead])
def sync_from_misp(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin")),
):
    client = MISPClient()
    synced = []
    for item in client.sync_iocs():
        ioc = db.query(IOC).filter(IOC.value == item["value"]).first()
        if not ioc:
            ioc = IOC(
                ioc_type=item["ioc_type"],
                value=item["value"],
                threat_level=item["threat_level"],
                source=item["source"],
                tags=item["tags"],
                description=item.get("description"),
            )
            db.add(ioc)
        else:
            ioc.threat_level = item["threat_level"]
            ioc.tags = item["tags"]
            ioc.source = item["source"]
            ioc.description = item.get("description")
        synced.append(ioc)
    db.commit()
    for item in synced:
        db.refresh(item)
    return synced


@router.get("/export/stix")
def export_stix(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst", "incident_responder")),
):
    iocs = db.query(IOC).order_by(IOC.id.asc()).all()
    return export_iocs_to_stix(iocs)


@router.post("/import/stix", response_model=list[IOCRead])
def import_stix(
    payload: dict,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    imported = []
    for item in import_iocs_from_stix(payload):
        existing = db.query(IOC).filter(IOC.value == item["value"]).first()
        if existing:
            imported.append(existing)
            continue
        ioc = IOC(**item)
        db.add(ioc)
        db.commit()
        db.refresh(ioc)
        imported.append(ioc)
    return imported


@router.get("/taxii/collection")
def taxii_collection(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst", "incident_responder")),
):
    iocs = db.query(IOC).order_by(IOC.id.asc()).all()
    return {
        "title": "Local Threat Intel TAXII Collection",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
        "objects": export_iocs_to_stix(iocs)["objects"],
    }

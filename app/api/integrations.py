from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import require_roles
from app.db.postgres import get_db
from app.schemas.integration import Module3ImportResult, Module3StatusResponse
from app.services.module3_integration import Module3IntegrationService

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("/module3/status", response_model=Module3StatusResponse)
def module3_status(
    _: object = Depends(require_roles("admin", "analyst", "incident_responder")),
):
    service = Module3IntegrationService()
    return service.status()


@router.post("/module3/import", response_model=Module3ImportResult)
async def import_module3_alerts(
    db: Session = Depends(get_db),
    _: object = Depends(require_roles("admin", "analyst")),
):
    service = Module3IntegrationService()
    try:
        return await service.import_and_forward(db)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

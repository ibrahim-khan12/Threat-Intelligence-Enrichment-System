from pydantic import BaseModel


class DemoRunResponse(BaseModel):
    alert_id: str
    created_ioc_id: int
    risk_score: int
    severity: str
    recommended_action: str


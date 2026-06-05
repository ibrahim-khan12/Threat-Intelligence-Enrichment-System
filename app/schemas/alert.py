from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AlertIn(BaseModel):
    alert_id: str
    source: str
    timestamp: datetime
    src_ip: str | None = None
    dest_ip: str | None = None
    domain: str | None = None
    url: str | None = None
    file_hash: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class AlertRead(BaseModel):
    id: int
    alert_id: str
    source: str
    timestamp: datetime
    severity: str
    status: str
    raw_payload: dict[str, Any]
    extracted_iocs: list[dict[str, Any]]
    summary: str | None = None

    model_config = {"from_attributes": True}


class EnrichedAlertRead(BaseModel):
    alert_id: str
    risk_score: int
    severity: str
    ioc_matches: list[dict[str, Any]]
    recommended_action: str
    mitre_attack: list[str] = Field(default_factory=list)
    sigma_matches: list[dict[str, Any]] = Field(default_factory=list)
    yara_matches: list[dict[str, Any]] = Field(default_factory=list)
    ai_classification: dict[str, Any] = Field(default_factory=dict)
    anomaly_score: int | None = None
    created_at: datetime | None = None

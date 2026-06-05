from datetime import datetime

from pydantic import BaseModel, Field


class IOCBase(BaseModel):
    ioc_type: str
    value: str
    threat_level: str = "medium"
    source: str = "manual"
    tags: list[str] = Field(default_factory=list)
    description: str | None = None


class IOCCreate(IOCBase):
    pass


class IOCUpdate(BaseModel):
    threat_level: str | None = None
    source: str | None = None
    tags: list[str] | None = None
    description: str | None = None


class IOCRead(IOCBase):
    id: int
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}

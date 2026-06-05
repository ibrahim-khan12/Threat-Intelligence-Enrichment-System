from pydantic import BaseModel


class Module3ImportResult(BaseModel):
    imported_alerts: int
    skipped_alerts: int
    handoff_records_written: int
    handoff_path: str


class Module3StatusResponse(BaseModel):
    source_path: str
    handoff_path: str
    source_exists: bool
    handoff_exists: bool

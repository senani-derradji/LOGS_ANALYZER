from pydantic import BaseModel
from datetime import datetime
from pydantic import class_validators
from pathlib import Path


class LogCreate(BaseModel):
    file_path: Path
    @class_validators.validator("file_path")
    def validate_file_path(cls, v):
        if not v.exists():
            raise ValueError("file_path does not exist")
        return v

    status: str = "pending"
    @class_validators.validator("status")
    def validate_status(cls, v):
        if v not in ["pending", "completed", "failed"]:
            raise ValueError("status must be pending, completed or failed")
        return v

    created_at: datetime = datetime.utcnow()

    class Config:
        from_attributes = True



class LogResponse(BaseModel):
    id: int
    file_path: str
    status: str

    class Config:
        from_attributes = True

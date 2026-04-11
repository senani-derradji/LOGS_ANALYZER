from pydantic import BaseModel
from datetime import datetime
from pydantic import class_validators
from pathlib import Path


class ResultResponse(BaseModel):
    id: int
    log_id: int
    user_id: int

    level: str
    message: str

    created_at: datetime

    class Config:
        from_attributes = True
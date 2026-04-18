from pydantic import BaseModel, Json
from datetime import datetime
from pydantic import class_validators
from pathlib import Path


class ResultResponse(BaseModel):
    log_id: int
    user_id: int

    level: str
    message: str
    details: Json | None = None
    ai_note: str

    class Config:
        from_attributes = True

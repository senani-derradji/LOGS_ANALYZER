from pydantic import BaseModel
from datetime import datetime
from pydantic import class_validators
from pathlib import Path
import os
from fastapi import HTTPException


class LogCreateValidator(BaseModel):
    file_path: Path

    @class_validators.validator("file_path")
    def validate_file_path(cls, v):
        if not v.exists():
            raise HTTPException(404, "file_path does not exist")
        if os.path.getsize(v) > 655000:
            raise HTTPException(status_code=404, detail="file size must be less than 5mb")
        return v

    file_name: str

    @class_validators.validator("file_name")
    def validate_file_name(cls, v):
        if v.endswith(".log"):
            return v
        else:
            raise HTTPException(404, "file_name must end with .log")

    status: str = "pending"

    @class_validators.validator("status")
    def validate_status(cls, v):
        if v not in ["pending", "completed", "failed"]:
            raise HTTPException(404, "status must be pending, completed or failed")
        return v

    class Config:
        from_attributes = True


class LogResponse(LogCreateValidator):
    id: int
    user_id: int

    class Config:
        from_attributes = True

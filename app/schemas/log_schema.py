from pydantic import BaseModel
from datetime import datetime
from pydantic import class_validators
from pathlib import Path


class LogCreateValidator(BaseModel):
    file_path: Path
    @class_validators.validator("file_path")
    def validate_file_path(cls, v):
        if not v.exists():
            raise ValueError("file_path does not exist")
        return v

    file_name: str
    @class_validators.validator("file_name")
    def validate_file_name(cls, v):
        if v.endswith(".log"):
            return v
        # else:
        #     raise ValueError("file_name must end with .log")



    status: str = "pending"
    @class_validators.validator("status")
    def validate_status(cls, v):
        if v not in ["pending", "completed", "failed"]:
            raise ValueError("status must be pending, completed or failed")
        return v

    class Config:
        from_attributes = True



class LogResponse(LogCreateValidator):
    id: int
    user_id: int

    class Config:
        from_attributes = True

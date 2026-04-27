from pydantic import BaseModel
from datetime import datetime
from pydantic import class_validators
from pathlib import Path
import os
from fastapi import HTTPException
from typing import Optional, Dict, Any, List


class LogCreateValidator(BaseModel):
    file_path: Path

    @class_validators.validator("file_path")
    def validate_file_path(cls, v):
        if not v.exists():
            raise HTTPException(404, "file_path does not exist")

        if not v.is_file():
            raise HTTPException(404, "file_path must be a file")

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
        if v not in ["pending", "processing", "completed", "failed"]:
            raise HTTPException(404, "status must be pending, processing, completed or failed")
        return v

    file_size: Optional[int] = None
    storage_size: Optional[int] = None


    class Config:
        from_attributes = True


class LogResponse(LogCreateValidator):
    id: int
    user_id: int

    file_size: Optional[int] = None
    total_lines: Optional[int] = None
    parsed_lines: Optional[int] = None
    unknown_lines: Optional[int] = None

    summary: Optional[Dict[str, Any]] = None
    levels_summary: Optional[Dict[str, Any]] = None
    top_ips: Optional[Dict[str, Any]] = None
    top_users: Optional[Dict[str, Any]] = None
    top_urls: Optional[Dict[str, Any]] = None
    templates_summary: Optional[Dict[str, Any]] = None
    signatures_summary: Optional[Dict[str, Any]] = None
    event_category_summary: Optional[Dict[str, Any]] = None
    correlations: Optional[Dict[str, Any]] = None
    anomalies: Optional[List[Dict[str, Any]]] = None

    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True

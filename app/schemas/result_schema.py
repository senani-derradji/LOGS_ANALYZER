from pydantic import BaseModel, Json
from datetime import datetime
from pydantic import class_validators
from pathlib import Path
from typing import Optional, List, Dict, Any


class ResultCreate(BaseModel):
    log_id: int
    user_id: int
    line_number: Optional[int] = None

    timestamp: Optional[str] = None
    normalized_timestamp: Optional[str] = None
    epoch: Optional[float] = None

    detected_type: Optional[str] = None
    level: Optional[str] = None
    message: Optional[str] = None

    template: Optional[str] = None
    signature: Optional[str] = None
    confidence: Optional[float] = None
    event_category: Optional[str] = None

    correlation: Optional[Dict[str, Any]] = None
    extra: Optional[Dict[str, Any]] = None
    signals: Optional[List[str]] = None

    details: Optional[Dict[str, Any]] = None
    ai_note: Optional[str] = None


class ResultResponse(BaseModel):
    id: int
    log_id: int
    user_id: int
    line_number: Optional[int] = None

    timestamp: Optional[str] = None
    normalized_timestamp: Optional[str] = None
    epoch: Optional[float] = None

    detected_type: Optional[str] = None
    level: Optional[str] = None
    message: Optional[str] = None

    template: Optional[str] = None
    signature: Optional[str] = None
    confidence: Optional[float] = None
    event_category: Optional[str] = None

    correlation: Optional[Dict[str, Any]] = None
    extra: Optional[Dict[str, Any]] = None
    signals: Optional[List[str]] = None

    details: Optional[Dict[str, Any]] = None
    ai_note: Optional[str] = None

    created_at: datetime

    class Config:
        from_attributes = True


class LogSummaryResponse(BaseModel):
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

    class Config:
        from_attributes = True

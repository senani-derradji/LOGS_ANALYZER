from sqlalchemy import Column, Integer, String, ForeignKey, Text, DateTime, JSON, Float
from datetime import datetime
from sqlalchemy.orm import relationship
from app.db.base import Base


class Result(Base):
    __tablename__ = "results"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(36), index=True, nullable=False)
    log_id = Column(Integer, ForeignKey("logs.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    line_number = Column(Integer, nullable=True)

    timestamp = Column(String(64), nullable=True)
    normalized_timestamp = Column(String(64), nullable=True)
    epoch = Column(Float, nullable=True)

    detected_type = Column(String(20), nullable=True)
    level = Column(String(20), nullable=True)
    message = Column(Text, nullable=True)

    template = Column(Text, nullable=True)
    signature = Column(String(32), nullable=True)
    confidence = Column(Float, nullable=True)
    event_category = Column(String(32), nullable=True)

    correlation = Column(JSON, nullable=True)
    extra = Column(JSON, nullable=True)
    signals = Column(JSON, nullable=True)

    details = Column(JSON, nullable=True)
    ai_note = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    log = relationship("Logs", back_populates="results")
    user = relationship("Users", back_populates="results")

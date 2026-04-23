from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from datetime import datetime
from sqlalchemy.orm import relationship
from app.db.base import Base


class Logs(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(36), index=True, nullable=False)

    file_path = Column(String(512), index=True, unique=True, nullable=False)
    file_name = Column(String(128), index=True, nullable=False)
    status = Column(String(20), default="pending")

    file_size = Column(Integer, nullable=True)
    storage_size = Column(Integer, default=0)
    total_lines = Column(Integer, default=0)
    parsed_lines = Column(Integer, default=0)
    unknown_lines = Column(Integer, default=0)

    summary = Column(JSON, nullable=True)
    levels_summary = Column(JSON, nullable=True)
    top_ips = Column(JSON, nullable=True)
    top_users = Column(JSON, nullable=True)
    top_urls = Column(JSON, nullable=True)
    templates_summary = Column(JSON, nullable=True)
    signatures_summary = Column(JSON, nullable=True)
    event_category_summary = Column(JSON, nullable=True)
    correlations = Column(JSON, nullable=True)
    anomalies = Column(JSON, nullable=True)

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    user = relationship("Users", back_populates="logs")
    results = relationship("Result", back_populates="log", cascade="all, delete-orphan")

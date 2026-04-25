from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON
from datetime import datetime, timedelta
from sqlalchemy.orm import relationship
from app.db.base import Base


class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(36), index=True, nullable=False)
    name = Column(String(50), index=True)
    email = Column(String(50), unique=True, index=True)
    password_hash = Column(String(256))
    role = Column(String(10), default="user")
    telegram_chat_id = Column(String(15), unique=True, index=True)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    subscription_tier = Column(String(20), default="free")
    subscription_expires_at = Column(DateTime, nullable=True, default=datetime.utcnow() + timedelta(days=30))
    monthly_quota = Column(Integer, default=100)
    api_usage_current_month = Column(Integer, default=0)
    api_usage_reset_at = Column(DateTime, nullable=True)

    invitation_token = Column(String(64), nullable=True)
    invitation_expires_at = Column(DateTime, nullable=True)

    email_verified = Column(Boolean, default=False)
    password_reset_token = Column(String(64), nullable=True)
    password_reset_expires_at = Column(DateTime, nullable=True)

    logs = relationship("Logs", back_populates="user")
    results = relationship("Result", back_populates="user")

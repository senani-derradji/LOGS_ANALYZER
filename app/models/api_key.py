from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from datetime import datetime
from sqlalchemy.orm import relationship
from app.db.base import Base


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(36), index=True, nullable=False)

    key_hash = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(50), nullable=False)
    prefix = Column(String(8), nullable=False)

    is_active = Column(Boolean, default=True)

    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    user = relationship("Users")
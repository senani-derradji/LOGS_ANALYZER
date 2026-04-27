from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from datetime import datetime
from sqlalchemy.orm import relationship
from app.db.base import Base



class InviteRequest(Base):
    __tablename__ = "invite_requests"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    status = Column(String, default="PENDING")
    created_at = Column(DateTime, default=datetime.utcnow)
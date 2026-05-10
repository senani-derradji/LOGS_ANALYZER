from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from datetime import datetime
from sqlalchemy.orm import relationship
from app.db.base import Base



class InviteRequest(Base):
    __tablename__ = "invite_requests"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    plan_type = Column(String, default="pro")
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)


class EnterpriseInviteRequest(Base):
    __tablename__ = "enterprise_invite_requests"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    company_name = Column(String)
    contact_person = Column(String)
    phone = Column(String, default="")
    message = Column(String, default="")
    plan_type = Column(String, default="enterprise")
    required_quota = Column(Integer, default=1000)
    status = Column(String, default="pending")
    token = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
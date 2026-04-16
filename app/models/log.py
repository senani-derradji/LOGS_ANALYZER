from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from datetime import datetime
from sqlalchemy.orm import relationship
from app.db.session import Base


class Logs(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)

    file_path = Column(String(256), index=True, unique=True, nullable=False)
    file_name = Column(String(32), index=True, nullable=False)
    status = Column(String(10), default="pending")

    created_at = Column(DateTime, default=datetime.utcnow)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    user = relationship("Users", back_populates="logs")
    results = relationship("Result", back_populates="log", cascade="all, delete-orphan")
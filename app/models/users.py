from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from sqlalchemy.orm import relationship


class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), index=True)
    email = Column(String(50), unique=True, index=True)
    password_hash = Column(String(256))
    role = Column(String(10))
    telegram_chat_id = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)

    logs = relationship("Logs", back_populates="user")
    results = relationship("Result", back_populates="user")
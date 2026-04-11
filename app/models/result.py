from sqlalchemy import Column, Integer, String, ForeignKey, Text, DateTime
from datetime import datetime
from sqlalchemy.orm import relationship
from app.db.session import Base

class Result(Base):
    __tablename__ = "results"

    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, ForeignKey("logs.id"))
    user_id = Column(Integer, ForeignKey("users.id"))

    level = Column(String)
    message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    log = relationship("Logs", back_populates="results")
    user = relationship("Users", back_populates="results")
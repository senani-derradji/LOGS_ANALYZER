from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from datetime import datetime
from sqlalchemy.orm import relationship


class Logs(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)

    file_path = Column(String(100))
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)

    user_id = Column(Integer, ForeignKey("users.id"))

    user = relationship("Users", back_populates="logs")
    results = relationship("Result", back_populates="log")
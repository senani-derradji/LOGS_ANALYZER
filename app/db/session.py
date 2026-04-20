from sqlalchemy.orm import sessionmaker
from app.db.base import engine
from app.utils.logger import logger
from app.db.base import Base
from app.models.users import Users
from app.models.log import Logs
from app.models.result import Result

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized successfully")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

from sqlalchemy.orm import sessionmaker
from app.db.base import Base, engine

from app.models.log import Logs
from app.models.result import Result
from app.models.users import Users

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    Base.metadata.create_all(bind=engine)
    print("Database initialized successfully")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

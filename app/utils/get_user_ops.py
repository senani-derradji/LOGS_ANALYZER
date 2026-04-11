from fastapi import Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.services.users import UserOperations
# from app.services.logs import LogOperations
# from app.services.results import ResultOperations

def get_user_ops(db: Session = Depends(get_db)):
    return UserOperations(db)


# def get_log_ops(db: Session = Depends(get_db)):
#     return LogOperations(db)


# def get_result_ops(db: Session = Depends(get_db)):
#     return ResultOperations(db)
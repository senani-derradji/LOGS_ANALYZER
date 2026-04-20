from app.models.result import Result
from fastapi import HTTPException
from app.schemas.result_schema import ResultResponse
from app.db.session import SessionLocal



class ResultOperations:
    def __init__(self, db = SessionLocal() ):
        self.db = db

    def get_results(self, skip: int = 0, limit: int = 100):
        results = self.db.query(Result).offset(skip).limit(limit).all()
        if results is not None:
            return results
        else:
            raise HTTPException(status_code=404, detail="Results not found")


    def create_result(self, result_data: dict):
        try:
            db_result = Result(
                    log_id=result_data["log_id"],
                    user_id=result_data["user_id"],
                    level=result_data["level"],
                    message=result_data["message"],
                    details=result_data["details"] if result_data.get("details") else None,
                    ai_note=result_data["ai_note"],
            )

            self.db.add(db_result)
            self.db.commit()
            self.db.refresh(db_result)

            return db_result

        except Exception as e:
            self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))
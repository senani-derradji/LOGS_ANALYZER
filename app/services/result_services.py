from app.models.result import Result
from fastapi import HTTPException
from app.schemas.result_schema import ResultResponse
from app.db.session import SessionLocal
from typing import Optional, List


class ResultOperations:
    def __init__(self, db = SessionLocal() ):
        self.db = db

    def get_results(self, skip: int = 0, limit: int = 100):
        results = self.db.query(Result).offset(skip).limit(limit).all()
        if results is not None:
            return results
        else:
            raise HTTPException(status_code=404, detail="Results not found")

    def get_result_by_id(self, result_id: int):
        result = self.db.query(Result).filter(Result.id == result_id).first()
        if result is not None:
            return result
        else:
            raise HTTPException(status_code=404, detail="Result not found")

    def get_results_by_log(self, log_id: int):
        results = self.db.query(Result).filter(Result.log_id == log_id).all()
        if results is not None:
            return results
        else:
            raise HTTPException(status_code=404, detail="Results not found")

    def get_results_by_level(self, level: str):
        results = self.db.query(Result).filter(Result.level == level).all()
        if results is not None:
            return results
        else:
            raise HTTPException(status_code=404, detail="Results not found")

    def get_results_by_type(self, detected_type: str):
        results = self.db.query(Result).filter(Result.detected_type == detected_type).all()
        if results is not None:
            return results
        else:
            raise HTTPException(status_code=404, detail="Results not found")

    def get_results_by_event_category(self, event_category: str):
        results = self.db.query(Result).filter(Result.event_category == event_category).all()
        if results is not None:
            return results
        else:
            raise HTTPException(status_code=404, detail="Results not found")

    def get_results_by_ip(self, ip: str):
        results = self.db.query(Result).filter(Result.extra["ip"].astext == ip).all()
        if results is not None:
            return results
        else:
            raise HTTPException(status_code=404, detail="Results not found")

    def get_results_by_user_extracted(self, user: str):
        results = self.db.query(Result).filter(Result.extra["user"].astext == user).all()
        if results is not None:
            return results
        else:
            raise HTTPException(status_code=404, detail="Results not found")

    def create_result(self, result_data: dict):
        try:
            db_result = Result(
                tenant_id=result_data["tenant_id"],
                log_id=result_data["log_id"],
                user_id=result_data["user_id"],
                line_number=result_data.get("line_number"),
                timestamp=result_data.get("timestamp"),
                normalized_timestamp=result_data.get("normalized_timestamp"),
                epoch=result_data.get("epoch"),
                detected_type=result_data.get("detected_type"),
                level=result_data.get("level"),
                message=result_data.get("message"),
                template=result_data.get("template"),
                signature=result_data.get("signature"),
                confidence=result_data.get("confidence"),
                event_category=result_data.get("event_category"),
                correlation=result_data.get("correlation"),
                extra=result_data.get("extra"),
                signals=result_data.get("signals"),
                details=result_data.get("details"),
                ai_note=result_data.get("ai_note"),
            )

            self.db.add(db_result)
            self.db.commit()
            self.db.refresh(db_result)

            return db_result

        except Exception as e:
            self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))

    def create_bulk_results(self, results_data: List[dict]):
        created_results = []
        try:
            for result_data in results_data:
                db_result = Result(
                    log_id=result_data["log_id"],
                    user_id=result_data["user_id"],
                    line_number=result_data.get("line_number"),
                    timestamp=result_data.get("timestamp"),
                    normalized_timestamp=result_data.get("normalized_timestamp"),
                    epoch=result_data.get("epoch"),
                    detected_type=result_data.get("detected_type"),
                    level=result_data.get("level"),
                    message=result_data.get("message"),
                    template=result_data.get("template"),
                    signature=result_data.get("signature"),
                    confidence=result_data.get("confidence"),
                    event_category=result_data.get("event_category"),
                    correlation=result_data.get("correlation"),
                    extra=result_data.get("extra"),
                    signals=result_data.get("signals"),
                    details=result_data.get("details"),
                    ai_note=result_data.get("ai_note"),
                )
                self.db.add(db_result)
                created_results.append(db_result)

            self.db.commit()
            for result in created_results:
                self.db.refresh(result)
            return created_results

        except Exception as e:
            self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))

    def delete_result(self, result_id: int):
        db_result = self.get_result_by_id(result_id)
        if db_result:
            try:
                self.db.delete(db_result)
                self.db.commit()
                return {"message": f"Result deleted successfully: {db_result.id}"}
            except Exception as e:
                self.db.rollback()
                raise HTTPException(status_code=500, detail=str(e))
        else:
            raise HTTPException(status_code=404, detail="Result not found")

    def delete_results_by_log(self, log_id: int):
        results = self.get_results_by_log(log_id)
        if results:
            try:
                for result in results:
                    self.db.delete(result)
                self.db.commit()
                return {"message": f"Deleted {len(results)} results for log {log_id}"}
            except Exception as e:
                self.db.rollback()
                raise HTTPException(status_code=500, detail=str(e))
        else:
            raise HTTPException(status_code=404, detail="Results not found")
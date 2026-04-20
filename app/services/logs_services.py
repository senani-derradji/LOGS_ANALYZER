from app.models.log import Logs
from fastapi import HTTPException
from app.schemas.log_schema import LogCreateValidator, LogResponse
from app.db.session import SessionLocal


class LogsOperations:
    def __init__(self, db = SessionLocal()):
        self.db = db

    def get_logs(self, skip: int = 0, limit: int = 100):
        logs = self.db.query(Logs).offset(skip).limit(limit).all()
        if logs is not None:
            return logs
        else:
            raise HTTPException(status_code=404, detail="Logs not found")

    def get_log_by_id(self, log_id: int):
        logs = self.db.query(Logs).filter(Logs.id == log_id).first()
        if logs is not None:
            return logs
        else:
            raise HTTPException(status_code=404, detail="Logs not found")

    def get_logs_by_user(self, user_id: int):
        logs = self.db.query(Logs).filter(Logs.user_id == user_id).all()
        if logs is not None:
            return logs
        else:
            raise HTTPException(status_code=404, detail="Logs not found")

    def create_log(self, log_data: LogCreateValidator, user_id: int):
        print("INSIDE CREATE LOG ...")

        if (
            self.db.query(Logs)
            .filter(Logs.file_path == str(log_data.file_path))
            .first()
        ):
            raise HTTPException(status_code=400, detail="Log already exists")

        if self.db.query(Logs).filter(Logs.user_id == user_id).count() >= 2:
            raise HTTPException(
                status_code=400, detail="Maximum number of logs reached for this user"
            )

        try:
            db_log = Logs(
                file_path=str(log_data.file_path),
                file_name=log_data.file_name,
                status=log_data.status,
                user_id=user_id,
            )

            self.db.add(db_log)
            self.db.commit()
            self.db.refresh(db_log)
            return db_log

        except Exception as e:
            self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))

    def change_status(self, log_id: int, new_status: str = "completed"):
        db_log = self.get_log_by_id(log_id)
        if db_log:
            try:
                if new_status:
                    db_log.status = new_status
                    self.db.commit()
                    return {"message" : f"status {db_log.status} changed"}

            except Exception as e:
                self.db.rollback()
                raise HTTPException(status_code=500, detail=str(e))
        else:
            raise HTTPException(status_code=404, detail="Log not found")

    def delete_log(self, log_id: int):
        db_log = self.get_log_by_id(log_id)
        if db_log:
            try:
                self.db.delete(db_log)
                self.db.commit()
                return {
                    "message": f"Log deleted successfully {db_log.file_name} : {db_log.id}"
                }
            except Exception as e:
                self.db.rollback()
                raise HTTPException(status_code=500, detail=str(e))
        else:
            raise HTTPException(status_code=404, detail="Log not found")

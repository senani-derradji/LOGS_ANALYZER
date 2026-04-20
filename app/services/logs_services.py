from app.models.log import Logs
from fastapi import HTTPException
from app.schemas.log_schema import LogCreateValidator, LogResponse
from app.db.session import SessionLocal
from datetime import datetime
import os


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
            file_size = os.path.getsize(str(log_data.file_path)) if os.path.exists(str(log_data.file_path)) else None

            db_log = Logs(
                file_path=str(log_data.file_path),
                file_name=log_data.file_name,
                status=log_data.status,
                file_size=file_size,
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
                    if new_status == "processing":
                        db_log.started_at = datetime.utcnow()
                    elif new_status in ("completed", "failed"):
                        db_log.completed_at = datetime.utcnow()
                    self.db.commit()
                    return {"message" : f"status {db_log.status} changed"}

            except Exception as e:
                self.db.rollback()
                raise HTTPException(status_code=500, detail=str(e))
        else:
            raise HTTPException(status_code=404, detail="Log not found")

    def update_log_summary(self, log_id: int, summary_data: dict):
        db_log = self.get_log_by_id(log_id)
        if db_log:
            try:
                if "summary" in summary_data:
                    db_log.summary = summary_data.get("summary")
                if "levels_summary" in summary_data:
                    db_log.levels_summary = summary_data.get("levels_summary")
                if "top_ips" in summary_data:
                    db_log.top_ips = summary_data.get("top_ips")
                if "top_users" in summary_data:
                    db_log.top_users = summary_data.get("top_users")
                if "top_urls" in summary_data:
                    db_log.top_urls = summary_data.get("top_urls")
                if "templates_summary" in summary_data:
                    db_log.templates_summary = summary_data.get("templates_summary")
                if "signatures_summary" in summary_data:
                    db_log.signatures_summary = summary_data.get("signatures_summary")
                if "event_category_summary" in summary_data:
                    db_log.event_category_summary = summary_data.get("event_category_summary")
                if "correlations" in summary_data:
                    db_log.correlations = summary_data.get("correlations")
                if "anomalies" in summary_data:
                    db_log.anomalies = summary_data.get("anomalies")
                if "total_lines" in summary_data:
                    db_log.total_lines = summary_data.get("total_lines")
                if "parsed_lines" in summary_data:
                    db_log.parsed_lines = summary_data.get("parsed_lines")
                if "unknown_lines" in summary_data:
                    db_log.unknown_lines = summary_data.get("unknown_lines")
                self.db.commit()
                self.db.refresh(db_log)
                return db_log
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

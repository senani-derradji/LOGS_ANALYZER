from app.models.log import Logs
from fastapi import HTTPException
from app.schemas.log_schema import LogCreateValidator, LogResponse
from app.db.session import SessionLocal
from datetime import datetime
import os
from app.utils.logger import logger
from sqlalchemy import func
from app.models.invite_requests import InviteRequest


class InviteOperations:
    def __init__(self, db=SessionLocal()):
        self.db = db

    def create_invite_request(self, email: str):
        try:
            db_invite = InviteRequest(
                email=email,
                status="PENDING",
                created_at=datetime.utcnow()
            )
            self.db.add(db_invite)
            self.db.commit()
            self.db.refresh(db_invite)
            return db_invite
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error creating invite request: {str(e)}")
            raise HTTPException(status_code=500, detail="Could not process invite request")

    def get_invite_request_by_email(self, email: str):

        return self.db.query(InviteRequest).filter(InviteRequest.email == email).first()

    def get_all_requests(self, skip: int = 0, limit: int = 100):

        return self.db.query(InviteRequest).offset(skip).limit(limit).all()

    def update_request_status(self, email: str, status: str):
        db_request = self.db.query(InviteRequest).filter(InviteRequest.email == email).first()
        if not db_request:
            raise HTTPException(status_code=404, detail="Invite request not found")

        db_request.status = status
        self.db.commit()
        self.db.refresh(db_request)
        return db_request

    def delete_request(self, email: str):

        db_request = self.db.query(InviteRequest).filter(InviteRequest.email == email).first()
        if not db_request:
            raise HTTPException(status_code=404, detail="Invite request not found")

        self.db.delete(db_request)
        self.db.commit()
        return {"message": "Invite request deleted successfully"}

    def change_status(self, email: str, new_status: str = "completed"):
        db_invite = self.get_invite_request_by_email(email)
        if db_invite:
            try:
                if new_status:
                    db_invite.status = new_status
                    self.db.commit()
                    self.db.refresh(db_invite)
                return db_invite
            except Exception as e:
                self.db.rollback()
                logger.error(f"Error updating log status: {str(e)}")
                raise HTTPException(status_code=500, detail="Could not update log status")
        else:
            raise HTTPException(status_code=404, detail="Log not found")
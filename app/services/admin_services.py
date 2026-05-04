from app.models.users import Users
from app.models.log import Logs
from app.models.result import Result
from app.models.invite_requests import InviteRequest
from app.services.logs_services import LogsOperations
from app.services.users_services import UserOperations
from app.services.result_services import ResultOperations
from app.services.invite_request_service import InviteOperations
from fastapi import HTTPException
from app.db.session import SessionLocal
from sqlalchemy import desc
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from app.schemas.users_schema import UserCreate, AdminCreateUser
from app.security.jwt import create_password_hash
from app.utils.logger import logger
import secrets
import string
import uuid
from app.utils.notification_manager import send_invite_email



class AdminOperations:
    def __init__(self, db=SessionLocal()):
        self.db = db

    def get_dashboard_stats(self) -> Dict[str, Any]:
        total_users = self.db.query(Users).count()
        active_users = self.db.query(Users).filter(Users.is_active == True).count()
        admin_users = self.db.query(Users).filter(Users.role == "admin").count()

        total_logs = self.db.query(Logs).count()
        pending_logs = self.db.query(Logs).filter(Logs.status == "pending").count()
        processing_logs = self.db.query(Logs).filter(Logs.status == "processing").count()
        completed_logs = self.db.query(Logs).filter(Logs.status == "completed").count()
        failed_logs = self.db.query(Logs).filter(Logs.status == "failed").count()

        total_results = self.db.query(Result).count()
        error_results = self.db.query(Result).filter(Result.level == "ERROR").all()
        warning_results = self.db.query(Result).filter(Result.level == "WARNING").all()
        info_results = self.db.query(Result).filter(Result.level == "INFO").all()
        debug_results = self.db.query(Result).filter(Result.level == "DEBUG").all()

        total_invite_requests = self.db.query(InviteRequest).count()
        pending_invite_requests = self.db.query(InviteRequest).filter(InviteRequest.status == "pending").count()
        completed_invite_requests = self.db.query(InviteRequest).filter(InviteRequest.status == "completed").count()
        rejected_invite_requests = self.db.query(InviteRequest).filter(InviteRequest.status == "rejected").count()

        return {
            "total_users": total_users,
            "active_users": active_users,
            "admin_users": admin_users,
            "total_logs": total_logs,
            "pending_logs": pending_logs,
            "processing_logs": processing_logs,
            "completed_logs": completed_logs,
            "failed_logs": failed_logs,
            "total_results": total_results,
            "error_count": len(error_results),
            "warning_count": len(warning_results),
            "info_count": len(info_results),
            "debug_count": len(debug_results),
            "total_invite_requests": total_invite_requests,
            "pending_invite_requests": pending_invite_requests,
            "completed_invite_requests": completed_invite_requests,
            "rejected_invite_requests": rejected_invite_requests
        }

    def get_recent_activity(self, days: int = 7) -> Dict[str, Any]:
        start_date = datetime.utcnow() - timedelta(days=days)

        recent_logs = self.db.query(Logs).filter(Logs.created_at >= start_date).all()
        recent_results = self.db.query(Result).filter(Result.created_at >= start_date).all()

        daily_stats = {}

        for log in recent_logs:
            if log.created_at:
                date_key = log.created_at.strftime("%Y-%m-%d")
                daily_stats[date_key] = daily_stats.get(date_key, 0) + 1

        for result in recent_results:
            if result.created_at:
                date_key = result.created_at.strftime("%Y-%m-%d")
                daily_stats[date_key] = daily_stats.get(date_key, 0) + 1

        daily_stats_array = [{"date": date, "count": count} for date, count in sorted(daily_stats.items())]

        return {
            "daily_stats": daily_stats_array,
            "period_days": days
        }

    def get_error_statistics(self) -> Dict[str, Any]:
        error_results = self.db.query(Result).filter(Result.level == "ERROR").all()
        warning_results = self.db.query(Result).filter(Result.level == "WARNING").all()
        info_results = self.db.query(Result).filter(Result.level == "INFO").all()
        debug_results = self.db.query(Result).filter(Result.level == "DEBUG").all()

        error_messages = {}
        for result in error_results:
            msg = result.message[:50] if result.message else "Unknown"
            error_messages[msg] = error_messages.get(msg, 0) + 1

        top_errors = sorted(error_messages.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_errors": len(error_results),
            "error_count": len(error_results),
            "warning_count": len(warning_results),
            "info_count": len(info_results),
            "debug_count": len(debug_results),
            "top_errors": [{"message": msg, "count": count} for msg, count in top_errors]
        }

    def get_user_statistics(self) -> Dict[str, Any]:
        users = self.db.query(Users).all()
        active_users_count = self.db.query(Users).filter(Users.is_active == True).count()

        users_with_logs = []
        for user in users:
            log_count = self.db.query(Logs).filter(Logs.user_id == user.id).count()
            result_count = self.db.query(Result).filter(Result.user_id == user.id).count()
            users_with_logs.append({
                "user_id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role,
                "logs_count": log_count,
                "results_count": result_count,
                "is_active": user.is_active
            })

        users_with_logs.sort(key=lambda x: x["logs_count"], reverse=True)

        return {
            "total_users": len(users_with_logs),
            "active_users": active_users_count,
            "users": users_with_logs
        }

    def get_all_tables(self) -> List[Dict[str, Any]]:
        return [
            {"name": "users", "model": "Users"},
            {"name": "logs", "model": "Logs"},
            {"name": "results", "model": "Result"}
        ]


class AdminLogsOperations(LogsOperations):
    def __init__(self, db=SessionLocal()):
        super().__init__(db)

    def get_logs_by_user(self, user_id: int):
        logs = self.db.query(Logs).filter(Logs.user_id == user_id).all()
        if logs is not None:
            return logs
        else:
            raise HTTPException(status_code=200, detail="Logs not found")


    def get_logs_admin(self, skip: int = 0, limit: int = 100):
        logs = self.db.query(Logs).offset(skip).limit(limit).all()
        return logs

    def update_log(self, log_id: int, log_data: dict):
        db_log = self.get_log_by_id(log_id)
        for key, value in log_data.items():
            if hasattr(db_log, key):
                setattr(db_log, key, value)
        self.db.commit()
        self.db.refresh(db_log)
        return db_log

    def bulk_delete_logs(self, log_ids: List[int]):
        deleted_count = 0
        for log_id in log_ids:
            try:
                db_log = self.db.query(Logs).filter(Logs.id == log_id).first()
                if db_log:
                    self.db.delete(db_log)
                    deleted_count += 1
            except Exception:
                continue
        self.db.commit()
        return {"message": f"Deleted {deleted_count} logs"}


class AdminUsersOperations(UserOperations):
    def __init__(self, db=SessionLocal()):
        super().__init__(db)

    def get_users(self, skip: int = 0, limit: int = 100, role: Optional[str] = None, is_active: Optional[bool] = None):
        query = self.db.query(Users)
        if role:
            query = query.filter(Users.role == role)
        if is_active is not None:
            query = query.filter(Users.is_active == is_active)
        return query.order_by(desc(Users.created_at)).offset(skip).limit(limit).all()

    def get_all_users(self, skip: int = 0, limit: int = 100):
        return self.db.query(Users).order_by(desc(Users.created_at)).offset(skip).limit(limit).all()

    def get_user_by_email(self, email: str):
        try:
            user = self.db.query(Users).filter(Users.email == email).first()
            if not user:
                return None
            return user
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def create_user(self, user: AdminCreateUser):
        import uuid

        db_user = self.get_user_by_email(user.email)
        if db_user is not None:
            raise HTTPException(
                status_code=400, detail=f"User already exists: {db_user.name}"
            )

        if user.role not in ["admin", "user"]:
            raise HTTPException(status_code=400, detail="Invalid role")

        if user.role == "user":
            is_active = True
            subscription_tier = "free"
            monthly_quota = 10
        else:
            is_active = True
            subscription_tier = "pro"
            monthly_quota = 100

        uid = str(uuid.uuid4())

        new_user = Users(
            name=user.name,
            email=user.email,
            password_hash=user.password,
            role=user.role,
            is_active=is_active,
            email_verified=True,
            created_at=datetime.utcnow(),
            tenant_id=uid,
            subscription_tier=subscription_tier,
            monthly_quota=monthly_quota,
        )
        try:
            self.db.add(new_user)
            self.db.commit()
            self.db.refresh(new_user)
            return new_user
        except Exception as e:
            self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))


class AdminResultsOperations(ResultOperations):
    def __init__(self, db=SessionLocal()):
        super().__init__(db)

    def get_results(self, skip: int = 0, limit: int = 100, level: Optional[str] = None):
        query = self.db.query(Result)
        if level:
            query = query.filter(Result.level == level)
        return query.order_by(desc(Result.created_at)).offset(skip).limit(limit).all()

    def update_result(self, result_id: int, result_data: dict):
        db_result = self.db.query(Result).filter(Result.id == result_id).first()
        if not db_result:
            raise HTTPException(status_code=404, detail="Result not found")
        for key, value in result_data.items():
            if hasattr(db_result, key):
                setattr(db_result, key, value)
        self.db.commit()
        self.db.refresh(db_result)
        return db_result

    def get_results_by_log(self, log_id: int):
        return self.db.query(Result).filter(Result.log_id == log_id).all()

    def get_results_by_user(self, user_id: int):
        return self.db.query(Result).filter(Result.user_id == user_id).all()

    def bulk_delete_results(self, result_ids: List[int]):
        deleted_count = 0
        for result_id in result_ids:
            try:
                db_result = self.db.query(Result).filter(Result.id == result_id).first()
                if db_result:
                    self.db.delete(db_result)
                    deleted_count += 1
            except Exception:
                continue
        self.db.commit()
        return {"message": f"Deleted {deleted_count} results"}


class AdminInviteRequestOperations(InviteOperations):
    def __init__(self, db=SessionLocal()):
        super().__init__(db)
        self.db = db

    def get_invite_requests(self, skip: int = 0, limit: int = 100):
        return self.db.query(InviteRequest).order_by(desc(InviteRequest.created_at)).offset(skip).limit(limit).all()

    def get_invite_request_by_email(self, email: str):
        return self.db.query(InviteRequest).filter(InviteRequest.email == email).first()

    def delete_invite_request(self, email: str):
        db_request = self.db.query(InviteRequest).filter(InviteRequest.email == email).first()
        if not db_request:
            raise HTTPException(status_code=404, detail="Invite request not found")
        self.db.delete(db_request)
        self.db.commit()
        return {"message": "Invite request deleted"}

    def change_invite_status(self, email: str, new_status: str = "completed"):
        db_invite = self.get_invite_request_by_email(email)
        if not db_invite:
            raise HTTPException(status_code=404, detail="Invite not found")
        try:
            if new_status:
                db_invite.status = new_status
                self.db.commit()
                self.db.refresh(db_invite)
            return db_invite
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error updating invite status: {str(e)}")
            raise HTTPException(status_code=500, detail="Could not update invite status")

    def bulk_delete_invite_requests(self, request_ids: List[int]):
        deleted_count = 0
        for request_id in request_ids:
            try:
                db_request = self.db.query(InviteRequest).filter(InviteRequest.id == request_id).first()
                if db_request:
                    self.db.delete(db_request)
                    deleted_count += 1
            except Exception:
                continue
        self.db.commit()
        return {"message": f"Deleted {deleted_count} invite requests"}

    def activate_invite_request(self, email: str):
        db_invite = self.get_invite_request_by_email(email)
        if not db_invite:
            raise HTTPException(status_code=404, detail="Invite request not found")
        if db_invite.status != "pending":
            raise HTTPException(status_code=400, detail=f"Invite request is already {db_invite.status}")

        # Check if user already exists
        existing_user = self.db.query(Users).filter(Users.email == email).first()
        if existing_user:
            raise HTTPException(status_code=400, detail=f"User with email {email} already exists")

        alphabet = string.ascii_letters + string.digits
        random_password = ''.join(secrets.choice(alphabet) for _ in range(12))

        # name_from_email = email.split('@')[0]


        password_hash = create_password_hash(random_password)

        uid = str(uuid.uuid4())
        new_user = Users(
            name=email.split('@')[0],
            email=email,
            password_hash=password_hash,
            role="user",
            is_active=True,
            email_verified=True,
            created_at=datetime.utcnow(),
            tenant_id=uid,
            subscription_tier="pro",
            monthly_quota=100,
        )
        try:
            self.db.add(new_user)
            self.db.commit()
            self.db.refresh(new_user)
        except Exception as e:
            self.db.rollback()
            raise HTTPException(status_code=500, detail=f"Failed to create user: {str(e)}")

        # Update invite status to activated
        try:
            db_invite.status = "activated"
            self.db.commit()
            self.db.refresh(db_invite)
        except Exception as e:
            self.db.rollback()
            raise HTTPException(status_code=500, detail=f"Failed to update invite status: {str(e)}")

        return {
            "message": "Invite activated successfully",
            "email": email,
            "password": random_password,
            "user_id": new_user.id,
            "status": "activated"
        }

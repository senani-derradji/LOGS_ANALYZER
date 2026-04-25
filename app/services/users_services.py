from app.models.users import Users
from app.schemas.users_schema import UserCreate, UserInDB, UserUpdate
from fastapi import HTTPException
from app.security.jwt import create_access_token, verify_password
from app.db.session import SessionLocal
from datetime import datetime, timedelta
from typing import Optional, Dict
from app.utils.logger import logger


TIER_QUOTAS = {
    "free": 100,
    "pro": 1000,
    "enterprise": 100000,
}


class UserOperations:
    def __init__(self, db = SessionLocal()):
        self.db = db

    def get_user_by_email(self, email: str):
        try:
            user = self.db.query(Users).filter(Users.email == email).first()
            if not user:
                return None
            return user
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def get_user_by_name(self, name: str):
        try:
            user = self.db.query(Users).filter(Users.name == name).first()
            if not user:
                return None
            return user
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def get_user_by_id(self, user_id: int):
        try:
            result = self.db.query(Users).filter(Users.id == user_id).first()
            if not result:
                return None
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def get_users(self, skip: int = 0, limit: int = 100):
        try:
            arr = []
            for i in self.db.query(Users).offset(skip).limit(limit).all():
                if i.is_active is True and i.role != "admin":
                    arr.append(i)

            return arr

        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def check_quota(self, user: Users) -> Dict[str, any]:
        tier = user.subscription_tier or "free"

        try:
            quota = int(user.monthly_quota)
        except (TypeError, ValueError):
            quota = TIER_QUOTAS.get(tier, TIER_QUOTAS["free"])

        usage = int(user.api_usage_current_month or 0)

        if user.subscription_expires_at and user.subscription_expires_at < datetime.utcnow():
            tier = "free"
            quota = TIER_QUOTAS["free"]

        logger.info(f"Quota: {quota}")
        logger.info(f"Usage: {usage}")
        logger.info(f"Tier: {tier}")

        logger.info(f"RESULT {user.subscription_expires_at} - {datetime.utcnow()}: {user.subscription_expires_at and user.subscription_expires_at < datetime.utcnow()}")

        remaining = max(0, quota - usage)
        allowed = usage < quota

        return {
            "allowed": allowed,
            "quota": quota,
            "usage": usage,
            "remaining": remaining,
            "tier": tier,
            "message": f"Quota exceeded ({usage}/{quota})" if not allowed else None
        }

    def increment_usage(self, user: Users):
        user.api_usage_current_month = (user.api_usage_current_month or 0) + 1

        now = datetime.utcnow()
        if not user.api_usage_reset_at or user.api_usage_reset_at < now:
            user.api_usage_current_month = 1
            user.api_usage_reset_at = now + timedelta(days=30)

        try:
            self.db.commit()
            self.db.refresh(user)
        except Exception as e:
            self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))

    def get_usage(self, user: Users) -> Dict[str, any]:
        return self.check_quota(user)


    def login_user(self, form_data):
        db_user = self.get_user_by_name(form_data.username)
        logger.debug(f"User lookup: {db_user}")
        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")

        password_hash = db_user.password_hash
        logger.debug(f"Password hash retrieved for user")
        if password_hash is None:
            raise HTTPException(status_code=400, detail="Invalid password")

        if db_user.is_active is True:
            if verify_password(form_data.password, db_user.password_hash):
                db_user.last_login = datetime.utcnow()
                self.db.commit()
                access_token = create_access_token(
                    data={"sub": db_user.email, "role": db_user.role}
                )
                return {"access_token": access_token, "token_type": "bearer"}
            else:
                raise HTTPException(status_code=400, detail="Invalid password")
        else:
            raise HTTPException(status_code=400, detail="User is not active")

    def update_user(self, user_id: int, user_update: UserUpdate):
        db_user = self.db.query(Users).filter(Users.id == user_id).first()
        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")

        update_data = user_update.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(db_user, key, value)
        try:
            self.db.commit()
            self.db.refresh(db_user)
        except Exception as e:
            self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))
        return db_user

    def delete_user(self, user_id: int):
        db_user = self.db.query(Users).filter(Users.id == user_id).first()
        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")
        try:
            self.db.delete(db_user)
            self.db.commit()
        except Exception as e:
            self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))
        return db_user

    def toggle_user_active(self, user_id: int):
        db_user = self.get_user_by_id(user_id)
        if not db_user:
            raise HTTPException(status_code=404, detail="User not found")
        db_user.is_active = not db_user.is_active
        self.db.commit()
        self.db.refresh(db_user)
        return db_user

    def change_user_role(self, user_id: int, new_role: str):
        db_user = self.get_user_by_id(user_id)
        if not db_user:
            raise HTTPException(status_code=404, detail="User not found")
        if new_role not in ("user", "admin"):
            raise HTTPException(status_code=400, detail="Role must be 'user' or 'admin'")
        db_user.role = new_role
        self.db.commit()
        self.db.refresh(db_user)
        return db_user

    def delete_user(self, user_id: int):
        db_user = self.db.query(Users).filter(Users.id == user_id).first()
        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")
        try:
            self.db.delete(db_user)
            self.db.commit()
        except Exception as e:
            self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))
        return db_user


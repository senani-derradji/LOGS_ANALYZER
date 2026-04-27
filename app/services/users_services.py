from app.models.users import Users
from app.schemas.users_schema import UserCreate, UserInDB, UserUpdate
from fastapi import HTTPException
from app.security.jwt import create_access_token, verify_password, create_password_hash
from app.db.session import SessionLocal
from datetime import datetime, timedelta
from typing import Optional, Dict
from app.utils.logger import logger
from app.utils.check_tier import check
import uuid


TIER_QUOTAS = {
    "free": 10,
    "pro": 1000,
    "enterprise": 100000,
}


class UserOperations:
    def __init__(self, db = SessionLocal()):
        self.db = db

    def create_user(self, user: UserCreate):
        db_user = self.get_user_by_email(user.email)
        if db_user:
            raise HTTPException(status_code=400, detail="Email already registered")

        db_user = self.get_user_by_name(user.name)
        if db_user:
            raise HTTPException(status_code=400, detail="Name already registered")

        hashed_password = create_password_hash(user.password)
        tenant_id = str(uuid.uuid4())

        db_user = Users(
            email=user.email,
            name=user.name,
            password_hash=hashed_password,
            is_active=False,
            tenant_id=tenant_id,

            subscription_tier=user.subscription_tier,

            monthly_quota=check(user.subscription_tier),

            subscription_expires_at=datetime.utcnow(),

            email_verified=False,

            api_usage_current_month=0,
            api_usage_reset_at=datetime.utcnow(),

            telegram_chat_id=user.telegram_chat_id if user.telegram_chat_id else None,

            created_at=datetime.now(),
        )
        self.db.add(db_user)
        self.db.commit()
        self.db.refresh(db_user)

        return db_user

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

        if db_user.email_verified is False:
            raise HTTPException(status_code=400, detail="Email not verified")

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

    def get_profile(self, user_email: str):
        db_user = self.get_user_by_email(user_email)
        UserInDB.model_validate(db_user)
        return {
            "UserData": UserInDB(**db_user.__dict__) if db_user else None,
            "Usage": self.check_quota(db_user)
        }

    def get_password_reset_token_data(self, email: str):
        db_user = self.get_user_by_email(email)
        if not db_user:
            raise HTTPException(status_code=404, detail="User not found")
        return {
            "token": db_user.password_reset_token,
            "expires_at": db_user.password_reset_expires_at,
                }

    def get_user_by_token(self, token: str):
        db_user = self.db.query(Users).filter(Users.password_reset_token == token).first()
        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")
        return db_user.email



from pydantic import BaseModel, EmailStr, field_validator
from datetime import datetime
from fastapi import HTTPException


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    telegram_chat_id: str
    invitation_token: str | None = None
    subscription_tier: str = "free"
    @field_validator("subscription_tier")
    @classmethod
    def validate_email(cls, v):
        if v not in ["free", "premium"]:
            raise HTTPException(status_code=400, detail="subscription_tier must be free or premium")
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if len(v) > 50:
            raise HTTPException(status_code=400, detail="name must be less than 50 characters")
        if not v or len(v) < 1:
            raise HTTPException(status_code=400, detail="name is required")
        return v

    class Config:
        from_attributes = True


class UserUpdate(BaseModel):
    name: str | None = None
    email: EmailStr | None = None
    password: str | None = None
    telegram_chat_id: str | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if v and len(v) > 50:
            raise HTTPException(status_code=400, detail="name must be less than 50 characters")
        return v

    class Config:
        from_attributes = True


class InviteCreate(BaseModel):
    email: EmailStr


class InviteResponse(BaseModel):
    token: str
    expires_at: datetime


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    token: str
    new_password: str


class UsageResponse(BaseModel):
    subscription_tier: str
    monthly_quota: int

class UserInDB(BaseModel):
    tenant_id: str
    name: str
    email: EmailStr
    is_active: bool
    api_usage_current_month: int
    api_usage_reset_at: datetime
    subscription_expires_at: datetime
    email_verified: bool
    telegram_chat_id: None | str

    class Config:
        from_attributes = True
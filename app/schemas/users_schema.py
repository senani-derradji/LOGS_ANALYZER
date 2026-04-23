from pydantic import BaseModel, EmailStr, field_validator
from datetime import datetime


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    telegram_chat_id: str
    invitation_token: str | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if len(v) > 50:
            raise ValueError("name must be less than 50 characters")
        if not v or len(v) < 1:
            raise ValueError("name is required")
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
            raise ValueError("name must be less than 50 characters")
        return v

    class Config:
        from_attributes = True


class UserInDB(BaseModel):
    id: int
    name: str
    email: EmailStr
    role: str
    telegram_chat_id: None | str
    created_at: datetime


class InviteCreate(BaseModel):
    email: EmailStr


class InviteResponse(BaseModel):
    token: str
    expires_at: datetime


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class UsageResponse(BaseModel):
    tier: str
    quota: int
    usage: int
    remaining: int

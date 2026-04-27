import secrets
import hashlib
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta
from app.utils.get_ops import get_user_ops
from app.services.users_services import UserOperations
from app.security.jwt import get_current_user
from app.models.users import Users
from app.db.session import SessionLocal
from app.models.api_key import ApiKey


class ApiKeyCreate(BaseModel):
    name: str
    # expires_in_days: int | None = 30
    # expired_in_hours: int | None = 24


class ApiKeyResponse(BaseModel):
    id: int
    name: str
    prefix: str
    is_active: bool
    created_at: datetime
    expires_at: datetime | None


class ApiKeyCreatedResponse(BaseModel):
    api_key: str
    key_id: int


api_keys_router = APIRouter()


@api_keys_router.post("/", response_model=ApiKeyCreatedResponse)
async def create_api_key(
    key_data: ApiKeyCreate,
    user=Depends(get_current_user),
    user_ops: UserOperations = Depends(get_user_ops),
):
    db_user = user_ops.get_user_by_email(user.get("sub"))
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    user_db = user_ops.get_user_by_email(user.get("sub"))

    raw_key = f"la_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    prefix = raw_key[:12]

    expires_at = None

    if user_db.subscription_tier == "free":
        expires_at = datetime.utcnow() + timedelta(hours=24)
    elif user_db.subscription_tier == "pro":
        expires_at = datetime.utcnow() + timedelta(days=30)
    elif user_db.subscription_tier == "enterprise":
        expires_at = datetime.utcnow() + timedelta(days=365)

    db = SessionLocal()
    try:
        api_key = ApiKey(
            tenant_id=db_user.tenant_id,
            key_hash=key_hash,
            name=key_data.name,
            prefix=prefix,
            user_id=db_user.id,
            expires_at=expires_at,
        )
        db.add(api_key)
        db.commit()
        db.refresh(api_key)
    finally:
        db.close()

    return ApiKeyCreatedResponse(api_key=raw_key, key_id=api_key.id)


@api_keys_router.get("/", response_model=list[ApiKeyResponse])
async def list_api_keys(
    user=Depends(get_current_user),
    user_ops: UserOperations = Depends(get_user_ops),
):
    db_user = user_ops.get_user_by_email(user.get("sub"))
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db = SessionLocal()
    try:
        keys = db.query(ApiKey).filter(ApiKey.user_id == db_user.id).all()
        return [
            ApiKeyResponse(
                id=k.id,
                name=k.name,
                prefix=k.prefix,
                is_active=k.is_active,
                created_at=k.created_at,
                expires_at=k.expires_at,
            )
            for k in keys
        ]
    finally:
        db.close()


@api_keys_router.delete("/{key_id}")
async def delete_api_key(
    key_id: int,
    user=Depends(get_current_user),
    user_ops: UserOperations = Depends(get_user_ops),
):
    db_user = user_ops.get_user_by_email(user.get("sub"))
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db = SessionLocal()
    try:
        api_key = db.query(ApiKey).filter(
            ApiKey.id == key_id,
            ApiKey.user_id == db_user.id
        ).first()
        if not api_key:
            raise HTTPException(status_code=404, detail="API key not found")

        db.delete(api_key)
        db.commit()
    finally:
        db.close()

    return {"message": "API key deleted"}
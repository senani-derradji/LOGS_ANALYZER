from fastapi import APIRouter, Depends, HTTPException
from typing import Optional
from pydantic import BaseModel
from app.utils.get_ops import get_user_ops
from app.services.users_services import UserOperations
from app.services.billing import billing_service
from app.security.jwt import get_current_user


class SubscriptionResponse(BaseModel):
    tier: str
    status: str
    expires_at: Optional[str] = None


class PortalResponse(BaseModel):
    url: str


billing_router = APIRouter()


@billing_router.get("/subscription", response_model=SubscriptionResponse)
async def get_subscription(
    user=Depends(get_current_user),
    user_ops: UserOperations = Depends(get_user_ops),
):
    db_user = user_ops.get_user_by_email(user.get("sub"))
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    return SubscriptionResponse(
        tier=db_user.subscription_tier or "free",
        status="active",
        expires_at=db_user.subscription_expires_at.isoformat() if db_user.subscription_expires_at else None
    )


@billing_router.post("/portal", response_model=PortalResponse)
async def create_portal_session(
    user=Depends(get_current_user),
    user_ops: UserOperations = Depends(get_user_ops),
):
    db_user = user_ops.get_user_by_email(user.get("sub"))
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    url = await billing_service.create_portal_session(db_user.email)
    if not url:
        raise HTTPException(status_code=400, detail="Billing not configured")

    return PortalResponse(url=url)
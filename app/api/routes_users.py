import secrets
import uuid
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from app.core.redis import get_redis

from app.services.users_services import UserOperations
from app.utils.get_ops import get_user_ops
from app.security.jwt import get_current_user, create_access_token, create_password_hash, verify_password
from app.schemas.users_schema import (
    UserCreate, InviteCreate, InviteResponse,
    ForgotPasswordRequest, ResetPasswordRequest, UsageResponse
)
from app.models.users import Users
from app.security.jwt import require_admin

from app.middleware.rate_limit import check_rate_limit
from fastapi import Request
from app.utils.check_tier import check
from app.utils.notification_manager import send_welcome_email, send_verification_email
from app.utils.logger import logger



class UserRoutes:
    def __init__(self):
        self.router = APIRouter()


        self.router.add_api_route("/login", self.user_login, methods=["POST"])
        self.router.add_api_route("/register", self.register, methods=["POST"])
        self.router.add_api_route("/profile", self.profile, methods=["GET"])
        self.router.add_api_route("/invite", self.create_invite, methods=["POST"])
        self.router.add_api_route("/forgot-password", self.forgot_password, methods=["POST"])
        self.router.add_api_route("/reset-password", self.reset_password, methods=["POST"])
        self.router.add_api_route("/usage", self.get_usage, methods=["GET"])
        self.router.add_api_route("/verify_email", self.verify_email, methods=["GET"])

    async def user_login(
        self,
        request_limit: Request,
        form_data: OAuth2PasswordRequestForm = Depends(),
        user_ops: UserOperations = Depends(get_user_ops),
    ):
        client_ip = request_limit.client.host

        allowed = await check_rate_limit(
            identifier=f"reset:{client_ip}",
            limit=5,
            period=300
        )

        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Too many reset attempts, try later"
            )
        return user_ops.login_user(form_data=form_data)



    async def register(
        self,
        request_limit: Request,
        user_data: UserCreate,
        user_ops: UserOperations = Depends(get_user_ops),
    ):
        client_ip = request_limit.client.host

        allowed = await check_rate_limit(
            identifier=f"reset:{client_ip}",
            limit=5,
            period=300
        )

        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Too many reset attempts, try later"
            )

        existing = user_ops.get_user_by_email(user_data.email)
        if existing:
            raise HTTPException(status_code=400, detail="Email already registered")

        tenant_id = str(uuid.uuid4())
        password_hash = create_password_hash(user_data.password)

        new_user = Users(
            tenant_id=tenant_id,
            name=user_data.name,
            email=user_data.email,
            password_hash=password_hash,
            telegram_chat_id=user_data.telegram_chat_id,

            role="user",
            subscription_tier="free",
            monthly_quota=100,

            email_verified=False,
            is_active=True,

            api_usage_current_month=0,
            api_usage_reset_at=datetime.utcnow() + timedelta(days=30),

            subscription_expires_at=datetime.utcnow() + timedelta(days=30),
        )

        user_ops.db.add(new_user)
        user_ops.db.commit()
        user_ops.db.refresh(new_user)

        redis_client = get_redis()

        token = secrets.token_urlsafe(32)
        verify_key = f"email_verify:{token}"

        await redis_client.set(
            verify_key,
            new_user.email,
            ex=3600,  # 1 hour
        )

        logger.info(f"verify_key created: {verify_key}")

        send_verification_email(
            to_email=new_user.email,
            name=new_user.name,
            token=token,
        )

        return {
            "message": "User created. Please verify your email.",
        }

    async def verify_email(
        self,
        token: str,
        user_ops: UserOperations = Depends(get_user_ops),
    ):
        redis_client = get_redis()

        verify_key = f"email_verify:{token}"
        email = await redis_client.get(verify_key)


        if not email:
            raise HTTPException(status_code=400, detail="Invalid or expired token")

        if isinstance(email, bytes):
            email = email.decode()

        user = user_ops.get_user_by_email(email)

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # FIX: correct field name
        user.email_verified = True
        user_ops.db.commit()

        await redis_client.delete(verify_key)

        send_welcome_email(
            to_email=user.email,
            name=user.name,
        )

        return {"message": "Email verified successfully"}

    async def create_invite(
        self,
        invite_data: InviteCreate,
        # user=Depends(get_current_user),
        # user_ops: UserOperations = Depends(get_user_ops),
        admin=Depends(require_admin),
    ):


        token = f"{secrets.token_urlsafe(32)}****{create_password_hash(invite_data.email)}"
        expires_at = datetime.utcnow() + timedelta(days=1)

        redis_client = get_redis()
        invite_key = f"invite:{token}"
        await redis_client.set(
            invite_key,
            invite_data.email,
            ex=1 * 24 * 60 * 60
        )

        return InviteResponse(token=token, expires_at=expires_at)

    async def forgot_password(
        self,
        request: ForgotPasswordRequest,
        user_ops: UserOperations = Depends(get_user_ops),
    ):
        user = user_ops.get_user_by_email(request.email)
        if not user:
            ####### i need to add resent logic here - sent link of resent #######
            return {"message": "If the email exists, a reset link has been sent"}

        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=1)

        user.password_reset_token = token
        user.password_reset_expires_at = expires_at
        user_ops.db.commit()

        redis_client = get_redis()
        reset_key = f"password_reset:{token}"
        await redis_client.set(
            reset_key,
            str(user.id),
            ex=3600
        )

        return {"message": "If the email exists, a reset link has been sent"}

    async def reset_password(
        self,
        request_limit: Request,
        request: ResetPasswordRequest,
        user_ops: UserOperations = Depends(get_user_ops),
    ):

        client_ip = request_limit.client.host

        allowed = await check_rate_limit(
            identifier=f"reset:{client_ip}",
            limit=5,
            period=300
        )

        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Too many reset attempts, try later"
            )

        redis_client = get_redis()
        reset_key = f"password_reset:{request.token}"
        user_id = await redis_client.get(reset_key)

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token")

        user = user_ops.get_user_by_id(int(user_id))
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.password_hash = create_password_hash(request.new_password)
        user.password_reset_token = None
        user.password_reset_expires_at = None
        user_ops.db.commit()

        await redis_client.delete(reset_key)

        return {"message": "Password reset successfully"}

    async def profile(self, user = Depends(get_current_user), user_ops: UserOperations = Depends(get_user_ops),):
        return {"message": "Authenticated User", "user": user_ops.get_profile(user_email=user.get("sub"))}

    async def get_usage(
        self,
        user=Depends(get_current_user),
        user_ops: UserOperations = Depends(get_user_ops),
    ):
        db_user = user_ops.get_user_by_email(user.get("sub"))
        if not db_user:
            raise HTTPException(status_code=404, detail="User not found")

        usage = user_ops.get_usage(db_user)
        return UsageResponse(
            tier=usage.get("tier"),
            quota=usage.get("quota"),
            usage=usage.get("usage"),
            remaining=usage.get("remaining")
        )

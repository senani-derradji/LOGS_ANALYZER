import secrets
import uuid
from fastapi import APIRouter, Depends, HTTPException, Form
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from app.core.redis import get_redis
from fastapi.responses import HTMLResponse

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
from app.utils.notification_manager import send_welcome_email, send_verification_email, send_reset_password_email
from app.utils.logger import logger
import time



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
        self.router.add_api_route("/reset-password-page", self.reset_password_page, methods=["GET"])

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

        await send_verification_email(
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

        await send_welcome_email(
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


        token = secrets.token_urlsafe(32)
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
            return {"message": "If the email exists, a reset link has been sent"}

        expires_at = datetime.utcnow() + timedelta(hours=1)
        token = secrets.token_urlsafe(32)



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
        user_ops.db.commit()

        logger.info(f"reset_key created: {reset_key}")


        await send_reset_password_email(
            to_email=user.email,
            name=user.name,
            token=token,
        )

        return {"message": "If the email exists, a reset link has been sent"}



    async def reset_password_page(self, token: str):

        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Reset Password</title>
        </head>

        <body style="font-family:Arial;background:#f4f6f8;display:flex;justify-content:center;align-items:center;height:100vh;">

            <div style="background:white;padding:30px;border-radius:10px;width:400px;box-shadow:0 4px 20px rgba(0,0,0,0.1);">

                <h2 style="color:#dc2626;">Reset Password</h2>


                <form method="POST" action="/api/v1/users/reset-password">

                    <input type="hidden" name="token" value="{token}" />

                    <label>New Password</label>
                    <input type="password" name="new_password"
                        style="width:100%;padding:10px;margin:10px 0;" required />

                    <label>Confirm Password</label>
                    <input type="password" name="confirm_password"
                        style="width:100%;padding:10px;margin:10px 0;" required />

                    <button type="submit"
                        style="width:100%;padding:12px;background:#dc2626;color:white;border:none;border-radius:6px;">
                        Reset Password
                    </button>

                </form>

            </div>

        </body>
        </html>
        """)

    async def reset_password(
        self,
        request_limit: Request,
        token: str = Form(...),
        new_password: str = Form(...),
        confirm_password: str = Form(...),
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

        if new_password and confirm_password:
            if new_password != confirm_password:
                raise HTTPException(status_code=400, detail="Passwords do not match")

            new_password_ = create_password_hash(new_password)
        else:
            raise HTTPException(status_code=400, detail="Invalid request")


        reset_key = f"password_reset:{token}"
        redis_client = get_redis()

        user_id = await redis_client.get(reset_key)

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token")

        user = user_ops.get_user_by_id(int(user_id))
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        token_db_data = user_ops.get_password_reset_token_data(user.email)
        if not token_db_data:
            raise HTTPException(status_code=404, detail="User not found")

        user.password_hash = new_password_
        user.password_reset_token = token
        user.password_reset_expires_at = datetime.utcnow() + timedelta(hours=1)

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
        return {
            "tier":usage.get("tier"),
            "quota":usage.get("quota"),
            "usage":usage.get("usage"),
            "remaining":usage.get("remaining")
        }

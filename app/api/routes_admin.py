from fastapi import APIRouter, HTTPException, Depends
from app.services.admin_services import (AdminOperations,
                                         AdminLogsOperations,
                                         AdminUsersOperations,
                                         AdminResultsOperations,
                                         AdminInviteRequestOperations)
from app.services.subscription_service import SubscriptionService
from app.models.users import Users
from app.utils.logger import logger
from app.schemas.users_schema import AdminCreateUser, UserCreate, UserInDB, UserUpdate, InviteCreate, InviteResponse, ActivateInviteResponse
from app.schemas.log_schema import LogResponse
from app.schemas.result_schema import ResultResponse
from app.security.jwt import require_admin
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from datetime import datetime, timedelta
import secrets
import string
from app.core.config import settings
from app.core.redis import get_redis
from app.utils.notification_manager import send_invite_email
from app.services.users_services import UserOperations


class RoleUpdate(BaseModel):
    role: str


class StatusUpdate(BaseModel):
    status: str


class BulkDeleteRequest(BaseModel):
    ids: List[int]


class EnterpriseSetup(BaseModel):
    user_id: int
    quota: int


class AdminRoutes:
    def __init__(self):
        self.router = APIRouter()

        self.router.add_api_route("/dashboard/stats", self.get_dashboard_stats, methods=["GET"])
        self.router.add_api_route("/dashboard/activity", self.get_recent_activity, methods=["GET"])
        self.router.add_api_route("/dashboard/errors", self.get_error_statistics, methods=["GET"])
        self.router.add_api_route("/dashboard/users", self.get_user_statistics, methods=["GET"])
        self.router.add_api_route("/tables", self.get_all_tables, methods=["GET"])

        self.router.add_api_route("/logs", self.get_logs, methods=["GET"])
        self.router.add_api_route("/logs/{log_id}", self.get_log, methods=["GET"])
        self.router.add_api_route("/logs/{log_id}", self.update_log, methods=["PUT"])
        self.router.add_api_route("/logs/{log_id}", self.delete_log, methods=["DELETE"])
        self.router.add_api_route("/logs/bulk-delete", self.bulk_delete_logs, methods=["POST"])

        self.router.add_api_route("/users", self.get_users, methods=["GET"])
        self.router.add_api_route("/users/all", self.get_all_users, methods=["GET"])
        self.router.add_api_route("/users/{user_id}", self.get_user, methods=["GET"])
        self.router.add_api_route("/users", self.create_user, methods=["POST"])
        self.router.add_api_route("/users/{user_id}", self.update_user, methods=["PUT"])
        self.router.add_api_route("/users/{user_id}", self.delete_user, methods=["DELETE"])
        self.router.add_api_route("/users/{user_id}/toggle-active", self.toggle_user_active, methods=["PATCH"])
        self.router.add_api_route("/users/{user_id}/role", self.change_user_role, methods=["PATCH"])
        self.router.add_api_route("/users/{user_id}/subscription", self.update_user_subscription, methods=["PATCH"])

        self.router.add_api_route("/results", self.get_results, methods=["GET"])
        self.router.add_api_route("/results/{result_id}", self.get_result, methods=["GET"])
        self.router.add_api_route("/results", self.create_result, methods=["POST"])
        self.router.add_api_route("/results/{result_id}", self.update_result, methods=["PUT"])
        self.router.add_api_route("/results/{result_id}", self.delete_result, methods=["DELETE"])
        self.router.add_api_route("/results/by-log/{log_id}", self.get_results_by_log, methods=["GET"])
        self.router.add_api_route("/results/by-user/{user_id}", self.get_results_by_user, methods=["GET"])
        self.router.add_api_route("/results/bulk-delete", self.bulk_delete_results, methods=["POST"])

        self.router.add_api_route("/invites", self.get_invites, methods=["GET"])
        self.router.add_api_route("/invites/{email}", self.get_invite, methods=["GET"])
        self.router.add_api_route("/invites", self.create_invite, methods=["POST"])
        self.router.add_api_route("/invites/{email}", self.delete_invite, methods=["DELETE"])
        self.router.add_api_route("/invites/{email}/status", self.change_invite_status, methods=["PATCH"])
        self.router.add_api_route("/invites/bulk-delete", self.bulk_delete_invites, methods=["POST"])

        # self.router.add_api_route("/enterprise-invites", self.get_enterprise_invites, methods=["GET"])
        # self.router.add_api_route("/enterprise-invites/{email}", self.get_enterprise_invite, methods=["GET"])
        # self.router.add_api_route("/enterprise-invites/{email}/setup", self.setup_enterprise, methods=["POST"])
        # self.router.add_api_route("/enterprise-invites/bulk-delete", self.bulk_delete_enterprise_invites, methods=["POST"])

    async def get_dashboard_stats(self, admin=Depends(require_admin)) -> Dict[str, Any]:
        ops = AdminOperations()
        return ops.get_dashboard_stats()

    async def get_recent_activity(self, days: int = 7, admin=Depends(require_admin)) -> Dict[str, Any]:
        ops = AdminOperations()
        return ops.get_recent_activity(days=days)

    async def get_error_statistics(self, admin=Depends(require_admin)) -> Dict[str, Any]:
        ops = AdminOperations()
        return ops.get_error_statistics()

    async def get_user_statistics(self, admin=Depends(require_admin)) -> Dict[str, Any]:
        ops = AdminOperations()
        return ops.get_user_statistics()

    async def get_all_tables(self, admin=Depends(require_admin)) -> List[Dict[str, Any]]:
        ops = AdminOperations()
        return ops.get_all_tables()

    async def get_logs(
        self,
        skip: int = 0,
        limit: int = 100,
        admin=Depends(require_admin)
    ):
        ops = AdminLogsOperations()
        return ops.get_logs_admin(skip=skip, limit=limit)

    async def get_log(self, log_id: int, admin=Depends(require_admin)):
        ops = AdminLogsOperations()
        return ops.get_log_by_id(log_id)

    async def update_log(self, log_id: int, log_data: Dict[str, Any], admin=Depends(require_admin)):
        ops = AdminLogsOperations()
        return ops.update_log(log_id, log_data)

    async def delete_log(self, log_id: int, admin=Depends(require_admin)):
        ops = AdminLogsOperations()
        return ops.delete_log(log_id)

    async def bulk_delete_logs(self, request: BulkDeleteRequest, admin=Depends(require_admin)):
        ops = AdminLogsOperations()
        return ops.bulk_delete_logs(request.ids)

    async def get_users(
        self,
        skip: int = 0,
        limit: int = 100,
        role: Optional[str] = None,
        is_active: Optional[bool] = None,
        admin=Depends(require_admin)
    ):
        ops = AdminUsersOperations()
        return ops.get_users(skip=skip, limit=limit, role=role, is_active=is_active)

    async def get_all_users(self, skip: int = 0, limit: int = 100, admin=Depends(require_admin)):
        ops = AdminUsersOperations()
        return ops.get_all_users(skip=skip, limit=limit)

    async def get_user(self, user_id: int, admin=Depends(require_admin)):
        ops = AdminUsersOperations()
        return ops.get_user_by_id(user_id)

    async def create_user(self, user_data: AdminCreateUser, admin=Depends(require_admin)):
        from app.security.jwt import create_password_hash
        ops = AdminUsersOperations()
        user_data.password = create_password_hash(user_data.password)
        logger.info(f"Creating user: {user_data.email}")
        return ops.create_user(user_data)

    async def update_user(self, user_id: int, user_data: Dict[str, Any], admin=Depends(require_admin)):
        ops = AdminUsersOperations()
        return ops.update_user(user_id, user_data)

    async def delete_user(self, user_id: int, admin=Depends(require_admin)):
        ops = AdminUsersOperations()
        return ops.delete_user(user_id)

    async def toggle_user_active(self, user_id: int, admin=Depends(require_admin)):
        ops = AdminUsersOperations()
        return ops.toggle_user_active(user_id)

    async def change_user_role(self, user_id: int, role_update: RoleUpdate, admin=Depends(require_admin)):
        ops = AdminUsersOperations()
        return ops.change_user_role(user_id, role_update.role)

    async def update_user_subscription(self, user_id: int, subscription_data: Dict[str, Any], admin=Depends(require_admin)):
        ops = AdminUsersOperations()
        return ops.update_user_subscription(user_id, subscription_data)

    async def get_results(
        self,
        skip: int = 0,
        limit: int = 100,
        level: Optional[str] = None,
        admin=Depends(require_admin)
    ):
        ops = AdminResultsOperations()
        return ops.get_results(skip=skip, limit=limit, level=level)

    async def get_result(self, result_id: int, admin=Depends(require_admin)):
        ops = AdminResultsOperations()
        return ops.get_result_by_id(result_id)

    async def create_result(self, result_data: Dict[str, Any], admin=Depends(require_admin)):
        ops = AdminResultsOperations()
        return ops.create_result(result_data)

    async def update_result(self, result_id: int, result_data: Dict[str, Any], admin=Depends(require_admin)):
        ops = AdminResultsOperations()
        return ops.update_result(result_id, result_data)

    async def delete_result(self, result_id: int, admin=Depends(require_admin)):
        ops = AdminResultsOperations()
        return ops.delete_result(result_id)

    async def get_results_by_log(self, log_id: int, admin=Depends(require_admin)):
        ops = AdminResultsOperations()
        return ops.get_results_by_log(log_id)

    async def get_results_by_user(self, user_id: int, admin=Depends(require_admin)):
        ops = AdminResultsOperations()
        return ops.get_results_by_user(user_id)

    async def bulk_delete_results(self, request: BulkDeleteRequest, admin=Depends(require_admin)):
        ops = AdminResultsOperations()
        return ops.bulk_delete_results(request.ids)

    async def get_invites(self, skip: int = 0, limit: int = 100, admin=Depends(require_admin)):
        ops = AdminInviteRequestOperations()
        return ops.get_invite_requests(skip=skip, limit=limit)

    async def create_invite(self, invite_data: InviteCreate, admin=Depends(require_admin)):
        from app.security.jwt import require_admin
        from app.services.users_services import UserOperations
        from app.core.redis import get_redis
        from app.utils.notification_manager import send_invite_email
        import secrets
        from datetime import datetime, timedelta

        email = invite_data.email
        plan_type = invite_data.plan_type or "pro"

        # Check if user already exists
        user_ops = UserOperations()
        db_user = user_ops.get_user_by_email(email)
        if not db_user:
            raise HTTPException(status_code=400, detail="User Not exists")

        # Check if invite request exists and is pending
        invite_ops = AdminInviteRequestOperations()
        db_invite = invite_ops.get_invite_request_by_email(email)
        # if not db_invite:
        #     raise HTTPException(status_code=404, detail="Invite request not found")
        if db_invite.status != "pending":
            raise HTTPException(status_code=400, detail="Invite request is not pending")

        # Determine quota based on plan_type
        if plan_type == "enterprise":
            subscription_tier = "enterprise"
            monthly_quota = 1000
        else:
            subscription_tier = "pro"
            monthly_quota = 100

        db_user.subscription_tier = subscription_tier
        db_user.monthly_quota = monthly_quota
        db_user.subscription_expires_at = datetime.utcnow() + timedelta(days=30)
        user_ops.db.commit()


        # # Create the user with proper quota
        # from app.security.jwt import create_password_hash
        # import uuid

        # alphabet = string.ascii_letters + string.digits
        # random_password = ''.join(secrets.choice(alphabet) for _ in range(12))
        # password_hash = create_password_hash(random_password)
        # uid = str(uuid.uuid4())

        # new_user = Users(
        #     name=email.split('@')[0],
        #     email=email,
        #     password_hash=password_hash,
        #     role="user",
        #     is_active=True,
        #     email_verified=True,
        #     created_at=datetime.utcnow(),
        #     tenant_id=uid,
        #     subscription_tier=subscription_tier,
        #     monthly_quota=monthly_quota,
        # )

        # try:
        #     invite_ops.db.add(new_user)
        #     invite_ops.db.commit()
        #     invite_ops.db.refresh(new_user)
        # except Exception as e:
        #     invite_ops.db.rollback()
        #     raise HTTPException(status_code=500, detail=f"Failed to create user: {str(e)}")

        # Update invite status to completed
        invite_ops.change_invite_status(email, "COMPLETED")

        # # Generate token for invite link
        # token = secrets.token_urlsafe(32)
        # expires_at = datetime.utcnow() + timedelta(days=1)

        # # Store in Redis
        # redis_client = get_redis()
        # invite_key = f"invite:{token}"
        # await redis_client.set(invite_key, email, ex=1 * 24 * 60 * 60)

        # # Send invite email with token
        # protocol = "https://" if settings.ENVIRONMENT == "production" else "http://"
        # domain = settings.DOMAIN if settings.DOMAIN else "localhost:8000"
        # invite_link = f"{protocol}{domain}/api/v1/users/invite-page?token={token}"
        # await send_invite_email(to_email=email, name=email.split('@')[0], invite_link=invite_link)

        # logger.info(f"User created: {email} with {subscription_tier} plan ({monthly_quota} logs/month)")
        # logger.info(f"invite_key created: {invite_key}")
        # logger.info(f"invite_endpoint: {invite_link}")

        return {
            "subscription tier" : subscription_tier,
            "Quota" : monthly_quota,
            "Status": "Completed"
        }
    async def get_invite(self, email: str, admin=Depends(require_admin)):
        ops = AdminInviteRequestOperations()
        invite = ops.get_invite_request_by_email(email)
        if not invite:
            raise HTTPException(status_code=404, detail="Invite request not found")
        return invite

    async def delete_invite(self, email: str, admin=Depends(require_admin)):
        ops = AdminInviteRequestOperations()
        return ops.delete_invite_request(email)

    async def change_invite_status(self, email: str, status_update: StatusUpdate, admin=Depends(require_admin)):
        ops = AdminInviteRequestOperations()
        return ops.change_invite_status(email, status_update.status)

    async def bulk_delete_invites(self, request: BulkDeleteRequest, admin=Depends(require_admin)):
        ops = AdminInviteRequestOperations()
        return ops.bulk_delete_invite_requests(request.ids)

    # async def activate_invite(self, email: str, admin=Depends(require_admin)):
    #     ops = AdminInviteRequestOperations()
    #     return ops.activate_invite_request(email)
        # invite = ops.get_enterprise_invite_by_email(email)
        # if not invite:
        #     raise HTTPException(status_code=404, detail="Enterprise invite not found")

        # user_ops = AdminUsersOperations()
        # existing_user = user_ops.get_user_by_email(email)
        # if existing_user:
        #     raise HTTPException(status_code=400, detail="User already exists")

        # alphabet = string.ascii_letters + string.digits
        # random_password = ''.join(secrets.choice(alphabet) for _ in range(12))
        # password_hash = create_password_hash(random_password)

        # uid = str(uuid.uuid4())
        # new_user = Users(
        #     name=invite.contact_person or email.split('@')[0],
        #     email=email,
        #     password_hash=password_hash,
        #     role="user",
        #     is_active=True,
        #     email_verified=True,
        #     created_at=datetime.utcnow(),
        #     tenant_id=uid,
        #     subscription_tier="enterprise",
        #     monthly_quota=setup.quota
        # )
        # try:
        #     ops.db.add(new_user)
        #     ops.db.commit()
        #     ops.db.refresh(new_user)
        # except Exception as e:
        #     ops.db.rollback()
        #     raise HTTPException(status_code=500, detail=f"Failed to create user: {str(e)}")

        # invite.status = "activated"
        # ops.db.commit()

        # return {
        #     "message": "Enterprise account created successfully",
        #     "email": email,
        #     "password": random_password,
        #     "user_id": new_user.id,
        #     "quota": setup.quota
        # }

    # async def bulk_delete_enterprise_invites(self, request: BulkDeleteRequest, admin=Depends(require_admin)):
    #     ops = EnterpriseInviteOperations()
    #     deleted_count = 0
    #     for invite_id in request.ids:
    #         try:
    #             db_invite = ops.db.query(EnterpriseInviteRequest).filter(EnterpriseInviteRequest.id == invite_id).first()
    #             if db_invite:
    #                 ops.db.delete(db_invite)
    #                 deleted_count += 1
    #         except Exception:
    #             continue
    #     ops.db.commit()
    #     return {"message": f"Deleted {deleted_count} enterprise invites"}
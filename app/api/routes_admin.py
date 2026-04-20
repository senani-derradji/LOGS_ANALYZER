from fastapi import APIRouter, HTTPException, Depends
from app.services.admin_services import AdminOperations, AdminLogsOperations, AdminUsersOperations, AdminResultsOperations
from app.schemas.users_schema import UserCreate, UserInDB, UserUpdate
from app.schemas.log_schema import LogResponse
from app.schemas.result_schema import ResultResponse
from app.security.jwt import require_admin
from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class RoleUpdate(BaseModel):
    role: str


class StatusUpdate(BaseModel):
    status: str


class BulkDeleteRequest(BaseModel):
    ids: List[int]


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

        self.router.add_api_route("/results", self.get_results, methods=["GET"])
        self.router.add_api_route("/results/{result_id}", self.get_result, methods=["GET"])
        self.router.add_api_route("/results", self.create_result, methods=["POST"])
        self.router.add_api_route("/results/{result_id}", self.update_result, methods=["PUT"])
        self.router.add_api_route("/results/{result_id}", self.delete_result, methods=["DELETE"])
        self.router.add_api_route("/results/by-log/{log_id}", self.get_results_by_log, methods=["GET"])
        self.router.add_api_route("/results/by-user/{user_id}", self.get_results_by_user, methods=["GET"])
        self.router.add_api_route("/results/bulk-delete", self.bulk_delete_results, methods=["POST"])

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
        return ops.get_logs(skip=skip, limit=limit)

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

    async def create_user(self, user_data: UserCreate, admin=Depends(require_admin)):
        from app.security.jwt import create_password_hash
        ops = AdminUsersOperations()
        # user_data = user.model_dump()
        user_data.password = create_password_hash(user_data.password)
        print("USER: DATA :: ", user_data)
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

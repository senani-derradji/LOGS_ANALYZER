from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, BackgroundTasks
from pathlib import Path
import shutil , json , os
from typing import Optional
from app.security.jwt import get_current_user
from app.schemas.log_schema import LogCreateValidator
from app.schemas.result_schema import ResultResponse
from app.utils.get_ops import get_log_ops, get_user_ops, get_result_ops
from app.services.logs_services import LogsOperations
from app.services.users_services import UserOperations
from app.services.result_services import ResultOperations
from app.utils.delete_file import delete_file
from app.utils.logger import logger
from app.core.redis import get_redis
from app.core.rabbitmq import send_log_job
from app.services.upload_service import upload_stream_to_r2
from app.services.api_key_auth_service import get_current_user_or_api_key



class LogsRoutes:
    def __init__(self):
        self.router = APIRouter()

        self.router.add_api_route("/upload", self.upload_file, methods=["POST"])
        self.router.add_api_route("/", self.get_logs, methods=["GET"])
        self.router.add_api_route("/{log_id}", self.get_log, methods=["GET"])
        self.router.add_api_route("/{log_id}", self.delete_log, methods=["DELETE"])
        self.router.add_api_route("/{log_id}/results", self.get_log_results, methods=["GET"])

        self.upload_dir = Path("uploads")
        self.upload_dir.mkdir(exist_ok=True)

    async def upload_file(
        self,
        background_tasks: BackgroundTasks,
        file: UploadFile = File(...),
        # user=Depends(get_current_user),
        user=Depends(get_current_user_or_api_key),
        logs_ops: LogsOperations = Depends(get_log_ops),
        user_ops: UserOperations = Depends(get_user_ops),
        res_ops: ResultOperations = Depends(get_result_ops),
    ):

        user_data = user_ops.get_user_by_email(user.get("sub"))
        quota = user_ops.check_quota(user_data)

        if not user_data:
            raise HTTPException(status_code=404, detail="User not found")

        if not user_data.tenant_id:
            raise HTTPException(status_code=400, detail="User tenant not configured")


        file.file.seek(0, 2)
        file_size = file.file.tell()
        file.file.seek(0)

        if user_data.subscription_tier == "free":
            if file_size > 1.01 * 1024 * 1024:
                raise HTTPException(
                    status_code=400,
                    detail="File size exceeds 1MB"
                )

        elif user_data.subscription_tier == "pro":
            if file_size > 5.01 * 1024 * 1024:
                raise HTTPException(
                    status_code=400,
                    detail="File size exceeds 5MB"
                )

        if user_data.monthly_quota <= user_data.api_usage_current_month:
            raise HTTPException(
                    status_code=403,
                    detail="Quota exceeded"
                )

        if not quota.get("allowed"):
            raise HTTPException(
                status_code=403,
                detail=quota.get("message", "Quota exceeded")
            )

        file_path = (
            self.upload_dir
            / Path(f"user_{user.get('sub').split('@')[0]}")
            / file.filename
        )

        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)


        background_tasks.add_task(
            upload_stream_to_r2,
            file_path,
            user.get("sub").split("@")[0],
            file_path.name,
            user_data.id
            )

        save_log = logs_ops.create_log(
            log_data=LogCreateValidator(
                file_path=str(file_path),
                file_name=file.filename,
                status="pending",
                file_size=file_size,
            ),
            user_id=user_data.id,
            tenant_id=user_data.tenant_id,
        )

        user_ops.increment_usage(user_data)

        job_data = {

            "file_path": str(file_path),
            "log_id": save_log.id,
            "user_id": user_data.id,
            "tenant_id": user_data.tenant_id,
            "retry": 0
        }

        await send_log_job(job_data)
        redis_client = get_redis()
        await redis_client.set(
            f"log:{job_data.get('log_id')}:status",
            "queued",
            ex=3600
        )

        return {
            "filename": file.filename,
            "path": str(file_path),
            "message": "File uploaded successfully",
            f"usage_{user_data.subscription_tier}": f"{quota.get('usage')}/{quota.get("remaining", 0)}",
            "size": f"{quota.get('usage')}/{quota.get('remaining', 0)}",
            "status": "processing"
        }

    async def get_logs(
        self,
        skip: int = 0,
        limit: int = 100,

        logs_ops: LogsOperations = Depends(get_log_ops),
        user=Depends(get_current_user),
        user_ops: UserOperations = Depends(get_user_ops),
    ):
        logs = logs_ops.get_logs(user_id=user_ops.get_user_by_email(user.get("sub")).id,
                                 skip=skip,
                                 limit=limit)

        if not logs:
            raise HTTPException(status_code=404, detail="Logs not found")
        return logs

    async def get_log(
        self,
        log_id: int,
        logs_ops: LogsOperations = Depends(get_log_ops),
        user=Depends(get_current_user),
        user_ops: UserOperations = Depends(get_user_ops),
    ):
        log = logs_ops.get_log_by_id(log_id)
        user_id = user_ops.get_user_by_email(user.get("sub")).id

        if not log:
            raise HTTPException(status_code=404, detail="Log not found")

        if log.user_id != user_id:
            raise HTTPException(
                status_code=403,
                detail="You are not authorized to get this log"
            )

        return log

    async def delete_log(
        self,
        log_id: int,
        logs_ops: LogsOperations = Depends(get_log_ops),
        user=Depends(get_current_user),
        user_ops: UserOperations = Depends(get_user_ops),
    ):
        log = logs_ops.get_log_by_id(log_id)

        if not log:
            raise HTTPException(status_code=404, detail="Log not found")

        user_id = user_ops.get_user_by_email(user.get("sub")).id

        if log.user_id != user_id:
            raise HTTPException(
                status_code=403,
                detail="You are not authorized to delete this log"
            )

        logs_ops.delete_log(log_id)

        try:
            delete_file(log.file_path)
        except FileNotFoundError:
            logger.error(f"File not found: {log.file_path}")

        return {"message": "Log deleted successfully"}

    async def get_log_results(
        self,
        log_id: int,
        skip: int = 0,
        limit: int = 100,
        level: Optional[str] = None,
        logs_ops: LogsOperations = Depends(get_log_ops),
        res_ops: ResultOperations = Depends(get_result_ops),
        user=Depends(get_current_user),
        user_ops: UserOperations = Depends(get_user_ops),
    ):
        log = logs_ops.get_log_by_id(log_id)
        user_id = user_ops.get_user_by_email(user.get("sub")).id

        if not log:
            raise HTTPException(status_code=404, detail="Log not found")

        if log.user_id != user_id:
            raise HTTPException(
                status_code=403,
                detail="You are not authorized to view results for this log"
            )

        results = res_ops.get_results_by_log_and_user(log_id, user_id, skip, limit, level)
        return results

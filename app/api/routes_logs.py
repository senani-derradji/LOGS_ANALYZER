from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, BackgroundTasks
from pathlib import Path
import shutil , json , os
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




class LogsRoutes:
    def __init__(self):
        self.router = APIRouter()

        self.router.add_api_route("/upload", self.upload_file, methods=["POST"])
        self.router.add_api_route("/", self.get_logs, methods=["GET"])
        self.router.add_api_route("/{log_id}", self.get_log, methods=["GET"])
        self.router.add_api_route("/{log_id}", self.delete_log, methods=["DELETE"])

        self.upload_dir = Path("uploads")
        self.upload_dir.mkdir(exist_ok=True)

    async def upload_file(
        self,
        background_tasks: BackgroundTasks,
        file: UploadFile = File(...),
        user=Depends(get_current_user),
        logs_ops: LogsOperations = Depends(get_log_ops),
        user_ops: UserOperations = Depends(get_user_ops),
        res_ops: ResultOperations = Depends(get_result_ops),
    ):
        user_data = user_ops.get_user_by_email(user.get("sub"))

        if not user_data:
            raise HTTPException(status_code=404, detail="User not found")

        if not user_data.tenant_id:
            raise HTTPException(status_code=400, detail="User tenant not configured")

        quota = user_ops.check_quota(user_data)
        if not quota.get("allowed"):
            raise HTTPException(
                status_code=403,
                detail=quota.get("message", "Quota exceeded")
            )

        if not file:
            raise HTTPException(status_code=400, detail="No file uploaded")

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
                status="pending"
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
        user_id = user_ops.get_user_by_email(user.get("sub")).id
        logs = logs_ops.get_logs_by_user(user_id)

        if not logs:
            raise HTTPException(status_code=404, detail="Logs not found")


        return logs


    async def get_log(
        self,
        log_id: int,
        logs_ops: LogsOperations = Depends(get_log_ops),
        user=Depends(get_current_user),
    ):
        log = logs_ops.get_log_by_id(log_id)

        if not log:
            raise HTTPException(status_code=404, detail="Log not found")

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
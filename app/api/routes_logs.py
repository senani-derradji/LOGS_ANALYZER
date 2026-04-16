from fastapi import APIRouter, UploadFile, File, HTTPException
from pathlib import Path
import shutil
from app.security.jwt import get_current_user, require_admin
from fastapi import Depends
from app.schemas.log_schema import LogCreateValidator
from app.utils.get_ops import get_log_ops
from app.utils.get_ops import get_user_ops
from app.services.logs_services import LogsOperations
from app.services.users_services import UserOperations



class LogsRoutes:
    def __init__(self):
        self.router = APIRouter()

        self.router.add_api_route("/upload", self.upload_file, methods=["POST"])
        self.router.add_api_route("/", self.get_logs, methods=["GET"])
        self.router.add_api_route("/{log_id}", self.get_log, methods=["GET"])
        self.router.add_api_route("/{log_id}", self.delete_log, methods=["DELETE"])

        self.upload_dir = Path("uploads")
        self.upload_dir.mkdir(exist_ok=True)

    async def upload_file(self, file: UploadFile = File(...),
                          user=Depends(get_current_user),
                          logs_ops: LogsOperations = Depends(get_log_ops),
                          user_ops: UserOperations = Depends(get_user_ops)):

        user_data = user_ops.get_user_by_email(user.get('sub'))

        if not file:
            raise HTTPException(status_code=400, detail="No file uploaded")

        file_path = self.upload_dir / Path(f"user_{user.get('sub').split('@')[0]}") / file.filename
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        print(file_path)


        save_log = logs_ops.create_log(
            log_data=LogCreateValidator(file_path=str(file_path), file_name=file.filename, status="pending"),
            user_id=user_data.id
        )

        return {
            "filename": file.filename,
            "path": str(file_path),
            "message": "File uploaded successfully"
        }


    async def get_logs(self,
                       skip: int = 0,
                       limit: int = 100,
                       logs_ops: LogsOperations = Depends(get_log_ops),
                       user=Depends(get_current_user),
                       user_ops: UserOperations = Depends(get_user_ops)
                       ):
        logs = logs_ops.get_logs_by_user(user_ops.get_user_by_email(user.get('sub')).id)
        if not logs:
            raise HTTPException(status_code=404, detail="Logs not found")
        return logs


    async def get_log(self,
                         log_id: int,
                         logs_ops: LogsOperations = Depends(get_log_ops),
                         user=Depends(get_current_user)):

        log = logs_ops.get_log_by_id(log_id)
        print(log.user_id)
        print(user.get('sub'))

        if not log:
            raise HTTPException(status_code=404, detail="Log not found")

        return log


    async def delete_log(self,
                         log_id: int,
                         logs_ops: LogsOperations = Depends(get_log_ops),
                         user=Depends(get_current_user),
                         user_ops: UserOperations = Depends(get_user_ops)):
        log = logs_ops.get_log_by_id(log_id)
        if not log:
            raise HTTPException(status_code=404, detail="Log not found")

        if log.user_id != user_ops.get_user_by_email(user.get('sub')).id:
            raise HTTPException(status_code=403, detail="You are not authorized to delete this log")

        logs_ops.delete_log(log_id) ; import os; os.remove(log.file_path)
        return {"message": "Log deleted successfully"}





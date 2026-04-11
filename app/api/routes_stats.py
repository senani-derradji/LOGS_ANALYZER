from app.utils.get_stats_device import (
    get_system_info,

)
from fastapi import APIRouter, HTTPException
from app.security.jwt import require_admin
from fastapi import Depends
from datetime import datetime


class StatisticsRoutes:
    def __init__(self):
        self.router = APIRouter()
        self.system_info = get_system_info()

        self.router.add_api_route("/system_info", self.get_stats, methods=["GET"])

    async def get_stats(self, admin=Depends(require_admin)):
        stats = get_system_info()
        return stats
from app.utils.get_stats_device import (
    get_system_info,
    get_cpu_info,
    get_memory_info,
    get_swap_info,
    get_disk_info,
    get_network_info,
    get_full_stats,
)
from fastapi import APIRouter, HTTPException
from app.security.jwt import require_admin
from fastapi import Depends


class StatisticsRoutes:
    def __init__(self):
        self.router = APIRouter()

        self.router.add_api_route("/system_info", self.get_stats, methods=["GET"])
        self.router.add_api_route("/full", self.get_full_system_stats, methods=["GET"])



    async def get_stats(self, admin=Depends(require_admin)):
        stats = get_system_info()
        return stats

    async def get_full_system_stats(self, admin=Depends(require_admin)):
        stats = get_full_stats()
        return stats

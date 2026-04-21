import psutil
import platform
import socket
from datetime import datetime


def get_redis_info():
    from app.core.redis import get_redis
    redis_client = get_redis()
    if not redis_client:
        return {"status": "disconnected"}

    try:
        info = redis_client.info()
        return {
            "status": "connected",
            "version": info.get("redis_version"),
            "uptime_seconds": info.get("uptime_in_seconds"),
            "used_memory": info.get("used_memory_human"),
            "used_memory_peak": info.get("used_memory_peak_human"),
            "connected_clients": info.get("connected_clients"),
            "total_connections_received": info.get("total_connections_received"),
            "total_commands_processed": info.get("total_commands_processed"),
            "keyspace": info.get("db0", {}).get("keys", 0),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}



def get_cpu_usage():
    return psutil.cpu_percent(interval=1)


def get_ram_usage():
    return psutil.virtual_memory().percent


def get_disk_usage():
    return psutil.disk_usage("/").percent


def get_basic_stats():
    return {
        "cpu_usage": get_cpu_usage(),
        "ram_usage": get_ram_usage(),
        "disk_usage": get_disk_usage(),
    }


def get_system_info():
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
    }


def get_cpu_info():
    return {
        "physical_cores": psutil.cpu_count(logical=False),
        "total_cores": psutil.cpu_count(logical=True),
        "usage_percent": psutil.cpu_percent(interval=1),
        "per_core_usage": psutil.cpu_percent(interval=1, percpu=True),
    }


def get_memory_info():
    vm = psutil.virtual_memory()
    return {
        "total": vm.total,
        "available": vm.available,
        "used": vm.used,
        "percent": vm.percent,
    }


def get_swap_info():
    swap = psutil.swap_memory()
    return {
        "total": swap.total,
        "used": swap.used,
        "free": swap.free,
        "percent": swap.percent,
    }


def get_disk_info():
    partitions = psutil.disk_partitions()
    disks = []

    for partition in partitions:
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            disks.append(
                {
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "filesystem": partition.fstype,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent,
                }
            )
        except PermissionError:
            continue

    return disks


def get_network_info():
    net = psutil.net_io_counters()
    return {
        "bytes_sent": net.bytes_sent,
        "bytes_recv": net.bytes_recv,
        "packets_sent": net.packets_sent,
        "packets_recv": net.packets_recv,
    }


def get_full_stats():
    return {
        "system": get_system_info(),
        "cpu": get_cpu_info(),
        "memory": get_memory_info(),
        "swap": get_swap_info(),
        "disk": get_disk_info(),
        "network": get_network_info(),
        # "redis": get_redis_info(),
        "time": datetime.utcnow().isoformat(),
    }

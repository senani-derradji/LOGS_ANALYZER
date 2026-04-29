from fastapi import Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_429_TOO_MANY_REQUESTS
from typing import Callable, Optional
import time
import hashlib

from app.core.redis import get_redis
from app.core.config import settings
from app.utils.logger import logger




class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, calls: int = 60, period: int = 60, key_prefix: str = "rate_limit"):
        super().__init__(app)
        self.calls = calls
        self.period = period
        self.key_prefix = key_prefix

    async def dispatch(self, request: Request, call_next: Callable):
        if settings.is_production and request.url.path in ["/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)

        # Skip rate limiting for OPTIONS requests (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        user_id = self._get_user_id(request)
        key = f"{self.key_prefix}:{user_id or client_ip}:{int(time.time() / self.period)}"
        logger.info(f"Rate limit key: {key}")
        redis_client = get_redis()
        if redis_client:
            try:
                current = await redis_client.incr(key)
                logger.info(f"Rate limit current: {current}")
                # Fix: await the ping() coroutine properly
                try:
                    ping_result = await redis_client.ping()
                    logger.info(f"redis status: {ping_result}")
                except Exception:
                    pass
                if current == 1:
                    await redis_client.expire(key, self.period)

                if current > self.calls:
                    return JSONResponse(
                        status_code=HTTP_429_TOO_MANY_REQUESTS,
                        content={"detail": "Rate limit exceeded", "retry_after": self.period}
                    )
            except Exception:
                pass

        return await call_next(request)

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _get_user_id(self, request: Optional[Request]) -> Optional[str]:
        if not request:
            return None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
            # Hash token to get a consistent, fixed-length identifier
            return hashlib.sha256(token.encode()).hexdigest()[:16]
        return None


def get_rate_limit(calls: int = 60, period: int = 60) -> Callable:
    def rate_limit_func(request: Request):
        pass
    return Depends(lambda: rate_limit_func)


async def check_rate_limit(identifier: str, limit: int = 60, period: int = 60) -> bool:
    redis_client = get_redis()
    if not redis_client:
        return True

    key = f"rate_limit:{identifier}:{int(time.time() / period)}"
    try:
        current = await redis_client.incr(key)
        logger.info(f"Rate limit current3: {current}")
        if current == 1:
            await redis_client.expire(key, period)
            logger.info(f"Rate limit current4: {current}")
        return current <= limit
    except Exception:
        return True
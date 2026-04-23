from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import text
from app.db.session import SessionLocal
from app.core.redis import get_redis
from app.core.config import settings
from pydantic import BaseModel


router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: str
    environment: str
    version: str = "1.0.0"


class ReadinessResponse(BaseModel):
    status: str
    database: str
    redis: str


@router.get("/healthz", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="ok",
        environment=settings.ENVIRONMENT
    )


@router.get("/readyz", response_model=ReadinessResponse)
async def readiness_check():
    db_status = "ok"
    redis_status = "ok"
    
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"error: {str(e)}"
    finally:
        db.close()
    
    redis_client = get_redis()
    if redis_client:
        try:
            await redis_client.ping()
        except Exception:
            redis_status = "error"
    else:
        redis_status = "not configured"
    
    if db_status != "ok" or redis_status != "ok":
        raise HTTPException(status_code=503, detail={
            "database": db_status,
            "redis": redis_status
        })
    
    return ReadinessResponse(
        status="ok",
        database=db_status,
        redis=redis_status
    )
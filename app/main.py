from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pathlib import Path
from app.db.session import init_db, SessionLocal
from app.models.users import Users
from app.security.jwt import create_password_hash
from app.api.routes_users import UserRoutes
from app.api.routes_stats import StatisticsRoutes
from app.api.routes_logs import LogsRoutes
from app.api.routes_admin import AdminRoutes
from app.api.routes_health import router as health_router
from app.api.routes_api_keys import api_keys_router
from app.api.routes_billing import billing_router
from app.core.redis import init_redis, close_redis
from app.core.config import settings
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.request_id import RequestIDMiddleware


def create_default_users():

    import random
    import uuid

    db = SessionLocal()

    try:
        users_data = [
            {
                "name": "derradji",
                "email": "derradji@localhost.com",
                "password": "admin",
                "role": "admin",
            },
            {
                "name": "admin",
                "email": "admin@localhost.com",
                "password": "admin",
                "role": "admin",
            },
            {
                "name": "user",
                "email": "user@example.com",
                "password": "password",
                "role": "user",
            },
        ]

        for u in users_data:
            existing = db.query(Users).filter(Users.email == u["email"]).first()
            if existing:
                continue

            user = Users(
                tenant_id=str(uuid.uuid4()),
                name=u["name"],
                email=u["email"],
                password_hash=create_password_hash(u["password"]),
                telegram_chat_id=random.randint(1000000000, 9999999999),
                role=u["role"],
                subscription_tier="free",
                monthly_quota=100,
            )

            db.add(user)

        db.commit()

    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    create_default_users()
    await init_redis()
    yield
    await close_redis()


app = FastAPI(
    title="Log Analyzer API",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=not settings.is_production,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(RequestIDMiddleware)
app.add_middleware(
    RateLimitMiddleware,
    calls=settings.RATE_LIMIT_PER_MINUTE,
    period=60,
    key_prefix="rate_limit"
)

user_routes = UserRoutes()
router_stats = StatisticsRoutes()
router_logs = LogsRoutes()
router_admin = AdminRoutes()

app.include_router(health_router, tags=["health"])

app.include_router(user_routes.router, prefix="/api/v1/users", tags=["users"])
app.include_router(router_stats.router, prefix="/api/v1/stats", tags=["stats"])
app.include_router(router_logs.router, prefix="/api/v1/logs", tags=["logs"])
app.include_router(router_admin.router, prefix="/api/v1/admin", tags=["admin"])
app.include_router(api_keys_router, prefix="/api/v1/api-keys", tags=["api-keys"])
app.include_router(billing_router, prefix="/api/v1/billing", tags=["billing"])


# @app.get("/")
# async def main_root():
#     return FileResponse("front/index.html")


# @app.get("/index.html")
# async def serve_index():
#     return FileResponse("front/index.html")


# @app.get("/css/{path:path}")
# async def serve_css(path: str):
#     return FileResponse(f"front/css/{path}")


# @app.get("/js/{path:path}")
# async def serve_js(path: str):
#     return FileResponse(f"front/js/{path}")


# @app.get("/libs/{path:path}")
# async def serve_libs(path: str):
#     file_path = f"front/libs/{path}"
#     if Path(file_path).is_file():
#         return FileResponse(file_path)
#     raise HTTPException(status_code=404, detail="File not found")
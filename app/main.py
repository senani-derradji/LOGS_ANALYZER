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
from app.core.redis import init_redis, close_redis


def create_super_user():
    import random

    db = SessionLocal()

    try:
        admins = ["derradji", "admin"]

        for admin in admins:
            user = db.query(Users).filter(Users.name == admin).first()
            if user:
                continue
            else:
                user = Users(
                    name=admin,
                    email=f"{admin}@localhost.com",
                    password_hash=create_password_hash("admin"),
                    telegram_chat_id=random.randint(1000000000, 9999999999),
                    role="admin",
                )

                db.add(user)
                db.commit()
                db.refresh(user)

    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    create_super_user()
    await init_redis()
    yield
    await close_redis()


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

user_routes = UserRoutes()
router_stats = StatisticsRoutes()
router_logs = LogsRoutes()
router_admin = AdminRoutes()

app.include_router(user_routes.router, prefix="/api/users", tags=["users"])
app.include_router(router_stats.router, prefix="/api/stats", tags=["stats"])
app.include_router(router_logs.router, prefix="/api/logs", tags=["logs"])
app.include_router(router_admin.router, prefix="/api/admin", tags=["admin"])


@app.get("/")
async def main_root():
    return FileResponse("front/index.html")


@app.get("/index.html")
async def serve_index():
    return FileResponse("front/index.html")


@app.get("/css/{path:path}")
async def serve_css(path: str):
    return FileResponse(f"front/css/{path}")


@app.get("/js/{path:path}")
async def serve_js(path: str):
    return FileResponse(f"front/js/{path}")


@app.get("/libs/{path:path}")
async def serve_libs(path: str):
    file_path = f"front/libs/{path}"
    if Path(file_path).is_file():
        return FileResponse(file_path)
    raise HTTPException(status_code=404, detail="File not found")

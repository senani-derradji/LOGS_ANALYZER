from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.db.session import init_db, SessionLocal
from app.models.users import Users
from app.security.jwt import create_password_hash
from app.api.routes_users import UserRoutes
from app.api.routes_stats import StatisticsRoutes
from app.api.routes_logs import LogsRoutes


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
                        role="admin"
                    )

                db.add(user) ; db.commit() ; db.refresh(user)

    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    create_super_user()
    yield


app = FastAPI(lifespan=lifespan)

user_routes = UserRoutes() ; router_stats = StatisticsRoutes() ; router_logs = LogsRoutes()

app.include_router(user_routes.router, prefix="/api/users", tags=["users"])
app.include_router(router_stats.router, prefix="/api/stats", tags=["stats"])
app.include_router(router_logs.router, prefix="/api/logs", tags=["logs"])


@app.get("/")
async def main_root():
    return {"message": "Welcome to the Main App"}
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm

from app.services.users import UserOperations
from app.schemas.users_schema import UserCreate, UserInDB, UserUpdate
from app.utils.get_user_ops import get_user_ops
from app.security.jwt import create_password_hash, get_current_user, require_admin


class UserRoutes:
    def __init__(self):
        self.router = APIRouter()

        self.router.add_api_route("/admin_panel", self.admin_panel, methods=["GET"])
        self.router.add_api_route("/login", self.user_login, methods=["POST"])
        self.router.add_api_route("/profile", self.profile, methods=["GET"])
        self.router.add_api_route("/", self.read_users, methods=["GET"], response_model=list[UserInDB])
        self.router.add_api_route("/{user_id}", self.delete_user, methods=["DELETE"])
        self.router.add_api_route("/create", self.create_user, methods=["POST"], response_model=UserInDB)
        self.router.add_api_route("/{user_id}", self.read_user, methods=["GET"], response_model=UserInDB)
        self.router.add_api_route("/email/{email}", self.read_user_by_email, methods=["GET"], response_model=UserInDB)
        self.router.add_api_route("/{user_id}", self.update_user, methods=["PUT"], response_model=UserInDB)

    async def admin_panel(self, admin=Depends(require_admin)):
        return {"message": "Admin Panel"}

    async def user_login(
        self,
        form_data: OAuth2PasswordRequestForm = Depends(),
        user_ops: UserOperations = Depends(get_user_ops)
    ):
        return user_ops.login_user(form_data=form_data)

    async def profile(self, user=Depends(get_current_user)):
        return {
            "message": "Authenticated User",
            "user": user
        }

    async def read_users(
        self,
        skip: int = 0,
        limit: int = 100,
        user_ops: UserOperations = Depends(get_user_ops),
        admin=Depends(require_admin)
    ):
        users = user_ops.get_users(skip=skip, limit=limit)
        if not users:
            raise HTTPException(status_code=404, detail="Users not found")
        return users

    async def delete_user(
        self,
        user_id: int,
        user_ops: UserOperations = Depends(get_user_ops),
        admin=Depends(require_admin)
    ):
        db_user = user_ops.delete_user(user_id=user_id)

        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")

        if db_user.role == "admin":
            raise HTTPException(status_code=403, detail="Cannot delete admin user")

        return {"message": "User deleted successfully"}

    async def create_user(
        self,
        user: UserCreate,
        user_ops: UserOperations = Depends(get_user_ops)
    ):
        user.password = create_password_hash(user.password)
        return user_ops.create_user(user=user)

    async def read_user(
        self,
        user_id: int,
        user_ops: UserOperations = Depends(get_user_ops)
    ):
        db_user = user_ops.get_user_by_id(user_id=user_id)

        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")

        return db_user

    async def read_user_by_email(
        self,
        email: str,
        user_ops: UserOperations = Depends(get_user_ops)
    ):
        db_user = user_ops.get_user_by_email(email=email)

        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")

        return db_user

    async def update_user(
        self,
        user_id: int,
        user_update: UserUpdate,
        user_ops: UserOperations = Depends(get_user_ops)
    ):
        db_user = user_ops.update_user(user_id=user_id, user_update=user_update)

        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")

        return db_user
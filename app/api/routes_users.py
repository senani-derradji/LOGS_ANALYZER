from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm

from app.services.users_services import UserOperations
from app.utils.get_ops import get_user_ops
from app.security.jwt import get_current_user


class UserRoutes:
    def __init__(self):
        self.router = APIRouter()

        self.router.add_api_route("/login", self.user_login, methods=["POST"])
        self.router.add_api_route("/profile", self.profile, methods=["GET"])

    async def user_login(
        self,
        form_data: OAuth2PasswordRequestForm = Depends(),
        user_ops: UserOperations = Depends(get_user_ops),
    ):
        return user_ops.login_user(form_data=form_data)

    async def profile(self, user=Depends(get_current_user)):
        return {"message": "Authenticated User", "user": user}

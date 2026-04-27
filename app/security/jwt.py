from datetime import datetime, timedelta, timezone
from typing import Dict, Any

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.hash import sha256_crypt

from app.core.config import settings


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/users/login")

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
ACCESS_TOKEN_EXPIRE_DAYS = 3


def create_password_hash(password: str) -> str:
    if not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password cannot be empty"
        )
    return sha256_crypt.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return sha256_crypt.verify(plain_password, hashed_password)


def create_access_token(
    data: Dict[str, Any],
    expires_delta: timedelta = timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS),
) -> str:

    if "sub" not in data:
        raise ValueError("Token payload must include 'sub' (subject/user id)")

    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        if not payload.get("sub"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token"
            )

        return payload

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return user

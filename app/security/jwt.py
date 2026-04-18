from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.hash import sha256_crypt
import os
from dotenv import load_dotenv

load_dotenv()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/users/login")
sec_key = os.getenv("SECRET_KEY", "secret")
alg = os.getenv("ALGORITHM", "HS256")


def create_password_hash(password):
    if not password:
        raise HTTPException(status_code=400, detail="Password is required")
    return sha256_crypt.hash(password)


def verify_password(plain_password, hashed_password):
    return sha256_crypt.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: timedelta = timedelta(days=3)):
    if "sub" not in data:
        raise ValueError("Token must contain 'sub' (user identifier)")

    to_encode = data.copy()

    expire = datetime.now() + expires_delta
    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, sec_key, algorithm=alg)

    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, sec_key, algorithms=[alg])
        email = payload.get("sub")

        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        return payload

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_admin(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

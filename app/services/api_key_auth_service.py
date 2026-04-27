from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional, Dict, Any
import hashlib

from app.db.session import get_db
from app.models.api_key import ApiKey
from app.models.users import Users
from app.security.jwt import get_current_user

from app.utils.logger import logger

http_bearer = HTTPBearer(auto_error=False)

def verify_api_key(api_key: str, db: Session) -> Optional[ApiKey]:
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    api_key_obj = db.query(ApiKey).filter(
        ApiKey.key_hash == key_hash,
        ApiKey.is_active == True
    ).first()

    if not api_key_obj:
        return None

    if api_key_obj.expires_at and api_key_obj.expires_at < datetime.utcnow():
        return None

    return api_key_obj


def get_api_key_user(api_key_obj: ApiKey, db: Session) -> Optional[Users]:
    user = db.query(Users).filter(
        Users.id == api_key_obj.user_id
    ).first()

    if not user:
        return None

    # update last used
    api_key_obj.last_used_at = datetime.utcnow()
    db.commit()

    return user


async def get_current_user_or_api_key(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:

    if credentials and credentials.scheme.lower() == "bearer":
        token = credentials.credentials

        try:
            user = await get_current_user(
                HTTPAuthorizationCredentials(
                    scheme="Bearer",
                    credentials=credentials.credentials
                )
            )
            user["auth_type"] = "jwt"
            return user
        except Exception:
            pass


    if credentials:
        api_key = credentials.credentials
        api_key_obj = verify_api_key(api_key, db)


        if not api_key_obj:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key"
            )

        user = get_api_key_user(api_key_obj, db)
        logger.info(f"USER: {user.email}")


        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )

        return {
            "sub": user.email,
            "role": user.role,
            "id": user.id,
            "tenant_id": user.tenant_id,
            "auth_type": "api_key"
        }


    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated"
    )
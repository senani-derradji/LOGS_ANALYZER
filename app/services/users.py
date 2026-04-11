from app.models.users import Users
from app.schemas.users_schema import UserCreate, UserInDB, UserUpdate
from fastapi import HTTPException
from app.security.jwt import create_access_token, verify_password
from sqlalchemy.orm import Session


class UserOperations:
    def __init__(self, db: Session):
        self.db = db


    def get_user_by_email(self, email: str):
        try:
            user = self.db.query(Users).filter(Users.email == email).first()
            if not user:
                return None
            return user
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def get_user_by_name(self, name: str):
        try:
            user = self.db.query(Users).filter(Users.name == name).first()
            if not user:
                return None
            return user
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))



    def get_user_by_id(self, user_id: int):
        try:
            result = self.db.query(Users).filter(Users.id == user_id).first()
            if not result:
                return None
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


    def get_users(self, skip: int = 0, limit: int = 100):
        try:
            arr = []
            for i in self.db.query(Users).offset(skip).limit(limit).all():
                if i.is_active is True and i.role != "admin":
                    arr.append(i)

            return arr
        
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


    def create_user(self, user: UserCreate):
        db_user = self.get_user_by_name(user.name)
        if db_user is not None:
            raise HTTPException(status_code=400, detail=f"User already exists: {db_user.name}")

        new_user = Users(
                    name=user.name,
                    email=user.email,
                    password_hash=user.password,
                    telegram_chat_id=user.telegram_chat_id,
                )
        try:
            self.db.add(new_user)
            self.db.commit()
            self.db.refresh(new_user)
            return new_user
        except Exception as e:
            self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))


    def login_user(self, form_data):
        db_user = self.get_user_by_name(form_data.username)
        print(db_user)
        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")

        password_hash = db_user.password_hash
        print(password_hash)
        if password_hash is None:
            raise HTTPException(status_code=400, detail="Invalid password")

        if db_user.is_active is True:
            if verify_password(form_data.password, db_user.password_hash):
                access_token = create_access_token(data={"sub": db_user.email, "role": db_user.role})
                return {
                        "access_token": access_token,
                        "token_type": "bearer"
                        }
            else:
                raise HTTPException(status_code=400, detail="Invalid password")
        else:
            raise HTTPException(status_code=400, detail="User is not active")


    def update_user(self, user_id: int, user_update: UserUpdate):
        db_user = self.db.query(Users).filter(Users.id == user_id).first()
        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")

        update_data = user_update.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(db_user, key, value)
        try:
            self.db.commit()
            self.db.refresh(db_user)
        except Exception as e:
            self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))
        return db_user


    def delete_user(self, user_id: int):
        db_user = self.db.query(Users).filter(Users.id == user_id).first()
        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")
        try:
            self.db.delete(db_user)
            self.db.commit()
        except Exception as e:
            self.db.rollback()
            raise HTTPException(status_code=500, detail=str(e))
        return db_user
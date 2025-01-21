from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import select

from src.auth.auth_utils import (
    authenticate_user,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    create_access_token,
    get_current_active_user,
)
from src.auth.models import User
from src.auth.schemas import UserInSchema, UserOutSchema, Token
from src.auth.service import UserService
from src.database import create_db_and_tables, SessionDep

router = APIRouter()


@router.get("", response_model=list[UserOutSchema])
def get_users(session: SessionDep):
    users = session.exec(select(User)).all()
    return users


@router.get("/{username}")
def get_user(username: str):
    return UserService.get_user_by_username(username)


@router.post("/sign_up", response_model=UserOutSchema)
def sign_up(user: UserInSchema):
    return UserService.create_user(user)


@router.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@router.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


@router.delete("/drop_database")
def drop_database():
    create_db_and_tables()
    return {"message": "Database dropped"}

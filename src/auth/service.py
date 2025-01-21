from sqlmodel import Session, select

from src.auth.auth_utils import get_password_hash
from src.auth.models import User
from src.auth.schemas import UserInSchema
from src.database import engine


class UserService:
    @classmethod
    def create_user(cls, user_in: UserInSchema):
        with Session(engine) as session:
            hashed_password = get_password_hash(user_in.password)
            user = User(
                username=user_in.username,
                hashed_password=hashed_password
            )
            session.add(user)
            session.commit()
            session.refresh(user)
            return user


    @classmethod
    def get_user_by_username(cls, username: str):
        with Session(engine) as session:
            statement = select(User).where(username == username)
            user = session.exec(statement).one_or_none()
            return user
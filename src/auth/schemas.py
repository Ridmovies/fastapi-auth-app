from pydantic import BaseModel


class UserInSchema(BaseModel):
    username: str
    password: str


class UserOutSchema(BaseModel):
    id: int
    username: str
    hashed_password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None

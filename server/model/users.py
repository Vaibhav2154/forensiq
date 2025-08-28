from pydantic import BaseModel, EmailStr, Field

class UserBase(BaseModel):
    email: EmailStr = Field(...)
    username: str = Field(...)

class UserCreate(UserBase):
    password: str = Field(...)

class LoginRequest(BaseModel):
    username: str = Field(...)
    password: str = Field(...)

class UserUpdate(BaseModel):
    email: str | None = None
    username: str | None = None
    full_name: str | None = None

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class UserInDB(UserBase):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None
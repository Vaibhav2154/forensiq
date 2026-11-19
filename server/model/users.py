from pydantic import BaseModel, EmailStr, Field

class UserBase(BaseModel):
    email: EmailStr = Field(...)
    username: str = Field(...)
    cli_active: bool = Field(default=False)

class UserCreate(UserBase):
    password: str = Field(...)

class LoginRequest(BaseModel):
    username: str = Field(...)
    password: str = Field(...)

class UserUpdate(BaseModel):
    email: str | None = None
    username: str | None = None
    cli_active: bool | None = None
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

class updatedUser(BaseModel):
    email:str|None = None
    username:str | None = None

class UserUpdateUsername(BaseModel):
    email: EmailStr
    username: str
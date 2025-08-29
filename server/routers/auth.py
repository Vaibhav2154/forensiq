from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from jose import JWTError, jwt
from core import  security
from core.config import settings
from model.users import UserBase,UserCreate,UserInDB,Token,TokenData,LoginRequest
from db import database

router = APIRouter(tags=["Authentication"])

# Updated tokenUrl to match the actual login endpoint path
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = await database.user_collection.find_one({"username": token_data.username})
    if user is None:
        raise credentials_exception
    return user

@router.post("/register", response_model=UserBase)
async def register_user(user: UserCreate):
    db_user = await database.user_collection.find_one({"email": user.email})
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = security.get_password_hash(user.password)
    user_in_db = UserInDB(
        email=user.email, 
        username=user.username, 
        hashed_password=hashed_password
    )
    
    await database.user_collection.insert_one(user_in_db.model_dump())
    return user_in_db

@router.post("/login", response_model=Token)
async def login(login_data: LoginRequest):
    """
    Login endpoint that supports JSON.
    
    - Use JSON body with LoginRequest for frontend integration
    """
    
    username_or_email = login_data.username
    password = login_data.password
    
    # Try to find user by email first (for frontend compatibility)
    user = await database.user_collection.find_one({"email": username_or_email})
    
    # If not found by email, try by username
    if not user:
        user = await database.user_collection.find_one({"username": username_or_email})
    
    if not user or not security.verify_password(password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = security.create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# COMMENTED OUT - Old login endpoint (keeping for reference)
# @router.post("/login", response_model=Token)
# async def login(login_data: LoginRequest,form_data : OAuth2PasswordRequestForm = Depends()):
#     #user = await database.user_collection.find_one({"email": login_data.username})
#     user = await database.user_collection.find_one({"email": form_data.username})
#     
#     if not user or not security.verify_password(form_data.password, user["hashed_password"]):
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username or password",
#             headers={"WWW-Authenticate": "Bearer"},
#         )
#     access_token = security.create_access_token(data={"sub": user["username"]})
#     return {"access_token": access_token, "token_type": "bearer"}

@router.get("/users/me", response_model=UserBase)
async def read_users_me(current_user: UserBase = Depends(get_current_user)):
    return current_user
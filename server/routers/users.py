from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional
from bson import ObjectId

from core import security
from core.config import settings
from model.users import UserBase,UserUpdate,PasswordChange,UserUpdateUsername
from db import database
from routers.auth import get_current_user

router = APIRouter(prefix="/users", tags=["Users"])

@router.put("/update-username", response_model=UserBase)
async def update_username(user_update: UserUpdateUsername):
    """Update username if email exists, otherwise error"""

    user = await database.user_collection.find_one({"email": user_update.email})
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")

    await database.user_collection.update_one(
        {"email": user_update.email},
        {"$set": {"username": user_update.username}}
    )

    user["username"] = user_update.username  # reflect change
    return UserBase(**user)



@router.put("/me", response_model=UserBase)
async def update_current_user(
    user_update: UserUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update the current user's profile information"""
    update_data = user_update.model_dump(exclude_unset=True)
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    # Check if email or username already exists (if being updated)
    if "email" in update_data:
        existing_email = await database.user_collection.find_one(
            {"email": update_data["email"], "username": {"$ne": current_user["username"]}}
        )
        if existing_email:
            raise HTTPException(status_code=400, detail="Email already registered")
    
    if "username" in update_data:
        # Skip check if user is updating to the same username
        if update_data["username"] != current_user["username"]:
            existing_username = await database.user_collection.find_one(
                {"username": update_data["username"]}
            )
            if existing_username:
                raise HTTPException(status_code=400, detail="Username already taken")
    
    # Update the user
    result = await database.user_collection.update_one(
        {"username": current_user["username"]},
        {"$set": update_data}
    )
    
    # Return updated user 
    updated_user = await database.user_collection.find_one({"username": current_user["username"]})
    return UserBase(**updated_user)


@router.put("/me/password")
async def change_password(
    password_change: PasswordChange,
    current_user: dict = Depends(get_current_user)
):
    """Change the current user's password"""
    # Verify current password
    if not security.verify_password(password_change.current_password, current_user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect current password"
        )
    
    # Hash new password
    new_hashed_password = security.get_password_hash(password_change.new_password)
    
    # Update password in database
    result = await database.user_collection.update_one(
        {"username": current_user["username"]},
        {"$set": {"hashed_password": new_hashed_password}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=400, detail="Password update failed")
    
    return {"message": "Password updated successfully"}

@router.delete("/me")
async def delete_current_user(current_user: dict = Depends(get_current_user)):
    """Delete the current user's account"""
    result = await database.user_collection.delete_one({"username": current_user["username"]})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=400, detail="Account deletion failed")
    
    return {"message": "Account deleted successfully"}

@router.get("/me", response_model=UserBase)
async def get_current_user_profile(current_user: dict = Depends(get_current_user)):
    """Get the current user's profile information"""
    return UserBase(**current_user)

from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from ...db import get_db
from ...services.users.users_crud import UserService
from ...shemas import UserCreate
from ...services.auth.dependencies import get_current_user

router = APIRouter(prefix="/api/users", tags=["User Management"])

@router.post("/create", summary="Create new user")
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    
    user_service = UserService(db)
    user_check = user_service.get_user_by_email(user.email)
    
    if user_check:
        raise HTTPException(
            status_code=400,
            detail=f"User exists already"
        )
    
    try:
        created_user = user_service.create_user(user)
        return {"message": "User has been created", "user": created_user}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create user: {str(e)}"
        )
    

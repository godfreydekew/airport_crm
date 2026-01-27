from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from ...db import get_db
from ...services.users.users_crud import UserService, ACCESS_TOKEN_EXPIRE_MINUTES
from ...shemas import UserCreate
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
    

@router.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Authenticate user and return access token."""
    user_service = UserService(db)
    user = user_service.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = user_service.create_access_token(
        data={"sub": user.full_name}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}
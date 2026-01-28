from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from ...db import get_db
from ...services.users.users_crud import UserService
from ...config import settings
from ...services.auth.dependencies import create_access_token, get_current_user
from ...shemas import UserCreate, UserResponse

auth_router = APIRouter(prefix="/api/auth", tags=["Authentication Management"])

@auth_router.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Authenticate user and return access token."""
    
    print("Login attempt for user:", form_data)
    userservice = UserService(db)
    user = userservice.authenticate_user(form_data.username, form_data.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.full_name}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@auth_router.get("/me", summary="Get current authenticated user", response_model=UserResponse)
def read_current_user(current_user: UserCreate = Depends(get_current_user)):
    """Retrieve the current authenticated user's information."""
    return current_user
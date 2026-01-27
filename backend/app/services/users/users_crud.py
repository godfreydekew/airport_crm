from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from typing import Optional, Union
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from ...models import User
from ...shemas import UserCreate, UserResponse, UserInDB

# Configuration
SECRET_KEY = "your-secret-key-here"  # In production, use environment variables
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserService:
    """Service class for user-related database operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create_user(self, user: UserCreate) -> User:
        """Create a new user with hashed password."""
        # Hash plain password
        hashed_password = pwd_context.hash(user.password)
        db_user = User(
            full_name=user.full_name,
            email=user.email,
            password_hash=hashed_password,
            is_active=True
        )
        
        self.db.add(db_user)
        self.db.commit()
        self.db.refresh(db_user)
        
        return db_user
    
    def get_user_by_id(self, user_id: int) -> Optional[UserInDB]:
        """Get user by ID."""
        return self.db.query(User).filter(User.id == user_id).first()
    
    def get_user_by_name(self, username: str) -> Optional[UserInDB]:
        """Get user by username."""
        return self.db.query(User).filter(User.full_name == username).first()
    
    def get_user_by_email(self, email: str) -> Optional[UserInDB]:
        """Get user by email."""
        return self.db.query(User).filter(User.email == email).first()
    
    def authenticate_user(self, name: str, password: str) -> Union[User, bool]:
        """Authenticate user with username and password."""
        user = self.get_user_by_name(name)
        if not user:
            return False
        if not pwd_context.verify(password, user.password_hash):
            return False
        return user
    
    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None):
        """Create a JWT access token."""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=15)

        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    def convert_db_user_to_user(self, db_user: User) -> UserResponse:
        """Convert database User model to UserResponse schema."""
        return UserResponse(
            id=db_user.id,
            full_name=db_user.full_name,
            email=db_user.email,
            is_active=db_user.is_active,
            created_at=db_user.created_at,
            updated_at=db_user.updated_at
        )
    
    async def get_current_user(self, token: str = Depends(oauth2_scheme)):
        """Get the current user from the JWT token."""
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            email: str = payload.get("sub")
            if email is None:
                raise credentials_exception
        except JWTError:
            raise credentials_exception

        db_user = self.get_user_by_email(email)
        if db_user is None:
            raise credentials_exception
        
        user = self.convert_db_user_to_user(db_user)
        return user

    async def get_current_active_user(self, current_user: UserResponse = Depends(get_current_user)):
        """Get the current active user (not disabled)."""
        if current_user.disabled:
            raise HTTPException(status_code=400, detail="Inactive user")
        return current_user
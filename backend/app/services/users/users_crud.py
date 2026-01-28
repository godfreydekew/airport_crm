from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from typing import Optional, Union
from ...models import User
from ...shemas import UserCreate, UserResponse, UserInDB
from ...config import settings


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserService:
    """Service class for user-related database operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def hash_password(self, password: str):
        hashed_password = pwd_context.hash(password)
        return hashed_password
    
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
 
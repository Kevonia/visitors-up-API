# app/auth.py
from datetime import datetime, timedelta
from typing import Optional

from requests import Session
from app.utilities.db_util import get_db
from app import crud
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from app.logging_config import logger
# Load settings
from app.config .config import settings

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# User model
class User(BaseModel):
    username: str
    password: str

# Fake user database
fake_users_db = {
    "admin": {
        "username": "admin",
        "password": pwd_context.hash("adminpassword")  # Hashed password
    }
}

# Verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Authenticate user
def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user or not verify_password(password, user["password"]):
        return None
    return User(**user)  # Return a User object

# Create access token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt

# Get current user
async def get_current_user(token: str = Depends(oauth2_scheme) ,db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decode the JWT token
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        email: str = payload.get("sub")
        if email is None:
            logger.warning("Invalid token: missing 'sub' field")
            raise credentials_exception

        # Fetch user from the database
        user = crud.get_user_by_email(db, email=email)
        if user is None:
            logger.warning(f"User not found for email: {email}")
            raise credentials_exception
            
        return user  # Return a User object
        
    except JWTError as e:
        logger.error(f"JWT error while decoding token: {str(e)}", exc_info=True)
        raise credentials_exception
    except Exception as e:
        logger.error(f"Unexpected error while fetching user details: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while fetching user details",
        )
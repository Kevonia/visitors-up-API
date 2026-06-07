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
import redis

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Shared Redis pool for token-blacklist checks (logout invalidates tokens here)
_redis_pool = redis.ConnectionPool.from_url(
    settings.REDIS_URL, max_connections=10, decode_responses=True
)


def _is_token_blacklisted(token: str) -> bool:
    """Check whether a token was invalidated via /logout. Fails open on Redis error."""
    try:
        conn = redis.Redis(connection_pool=_redis_pool)
        try:
            return conn.exists(f"token_blacklist:{token}") == 1
        finally:
            conn.close()
    except redis.RedisError as e:
        logger.error(f"Redis error checking token blacklist: {str(e)}")
        return False

# Minimal user schema kept for back-compat with app.zoho_integration.routes.
class User(BaseModel):
    username: str
    password: str

# Verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

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
        # Reject tokens that were invalidated on logout
        if _is_token_blacklisted(token):
            logger.warning("Rejected blacklisted (logged-out) token")
            raise credentials_exception

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
        


def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=30)  # Refresh tokens last longer
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)

def verify_refresh_token(token: str):
    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except JWTError:
        raise invalid
    # Reject access tokens replayed at the refresh endpoint: only tokens minted
    # by create_refresh_token (type == "refresh") may mint new access tokens.
    if payload.get("type") != "refresh":
        logger.warning("Refresh rejected: token is not a refresh token")
        raise invalid
    return payload


def require_roles(*allowed_roles: str):
    """Dependency factory enforcing that the current user has one of the given roles.

    Usage:
        @router.get(..., dependencies=[Depends(require_roles("ADMIN"))])
        def handler(user = Depends(require_roles("SECURITY", "ADMIN"))):
            ...
    """
    allowed = {r.upper() for r in allowed_roles}

    async def _checker(current_user=Depends(get_current_user)):
        role_name = (current_user.role.name if current_user.role else "") or ""
        if role_name.upper() not in allowed:
            logger.warning(
                f"Forbidden: user {getattr(current_user, 'email', '?')} role "
                f"'{role_name}' not in {sorted(allowed)}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource.",
            )
        return current_user

    return _checker
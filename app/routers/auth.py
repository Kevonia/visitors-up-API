import logging
from app.config.auth import verify_refresh_token
from app import models
from app.zoho_integration.zoho_client import ZohoClient
from fastapi import FastAPI, Depends, HTTPException, status, APIRouter, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from .. import crud, schemas
from ..utilities.db_util import get_db
from app.config.config import settings
from ..utilities.authutil import get_password_hash, verify_password, create_access_token,create_refresh_token
from jose import JWTError, jwt
from app.logging_config import logger
from aiocache import cached
import redis
from datetime import datetime, timedelta
from passlib.context import CryptContext
from typing import Optional
import time
import json

router = APIRouter()
zoho_client = ZohoClient()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login")
# Protected routes with authentication and caching
cache_timer = 3600




logger = logging.getLogger(__name__)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Initialize Redis connection pool
redis_pool = redis.ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=10,
    decode_responses=True
)

@router.post("/login", response_model=schemas.Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
    request: Request = None
):
    """
    Authenticate user and return JWT access token with rate limiting and security logging.
    """
    # Initialize metrics and client info
    login_attempt_time = time.time()
    client_ip = request.client.host if request else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    try:
        logger.info(
            f"Login attempt for user: {form_data.username} from IP: {client_ip}",
            extra={
                "tags": {
                    "action": "login_attempt",
                    "user": form_data.username,
                    "ip": client_ip,
                    "user_agent": user_agent
                }
            }
        )

        # Rate limiting check
        if is_rate_limited(form_data.username, client_ip):
            logger.warning(
                f"Rate limited login attempt for {form_data.username} from {client_ip}",
                extra={"tags": {"security": "rate_limit", "severity": "high"}}
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Please try again later.",
            )

        # Fetch user with status check
        user = crud.get_user_by_email(db, email=form_data.username)
        if not user:
            log_failed_attempt(form_data.username, client_ip, user_agent, "invalid_username")
            logger.warning(
                f"User not found: {form_data.username}",
                extra={"tags": {"security": "invalid_username", "severity": "medium"}}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check user status
        # if not user.is_active:
        #     log_failed_attempt(form_data.username, client_ip, user_agent, "inactive_account")
        #     logger.warning(
        #         f"Inactive user login attempt: {user.email}",
        #         extra={"tags": {"security": "inactive_account", "severity": "medium"}}
        #     )
        #     raise HTTPException(
        #         status_code=status.HTTP_403_FORBIDDEN,
        #         detail="Account is inactive. Please contact support.",
        #     )

        # Verify password with timing attack protection
        if not verify_password(form_data.password, user.hashed_password):
            log_failed_attempt(form_data.username, client_ip, user_agent, "invalid_password")
            logger.warning(
                f"Invalid password for user: {user.email}",
                extra={"tags": {"security": "invalid_password", "severity": "medium"}}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Generate JWT token
        access_token = create_access_token(
            data={
                "sub": user.email,
                "user_id": str(user.id),
                "role": user.role.name if user.role else None,
                # "iss": settings.JWT_ISSUER,
                # "aud": settings.JWT_AUDIENCE,
            }
        )
        refresh_token = create_refresh_token(
            data={
                "sub": user.email,
                "user_id": str(user.id),
                "role": user.role.name if user.role else None,
                # "iss": settings.JWT_ISSUER,
                # "aud": settings.JWT_AUDIENCE,
            }
        )
        # Log successful login
        login_duration = (time.time() - login_attempt_time) * 1000
        logger.info(
            f"Login successful for user: {user.email} (took {login_duration:.2f}ms)",
            extra={
                "tags": {
                    "action": "login_success",
                    "duration_ms": login_duration,
                    "user_id": user.id
                }
            }
        )

        # Reset rate limiting on successful login
        reset_rate_limit(form_data.username, client_ip)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.access_token_expire_minutes * 60
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.critical(
            f"Unexpected login error for {form_data.username}: {str(e)}",
            exc_info=True,
            extra={"tags": {"error": "unexpected_login_error", "severity": "critical"}}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during authentication",
        )

def is_rate_limited(username: str, ip: str) -> bool:
    """
    Check if login attempts should be rate limited using Redis.
    Limits:
    - 5 attempts per username per hour
    - 20 attempts per IP address per hour
    """
    redis_conn = redis.Redis(connection_pool=redis_pool)
    try:
        # Check username rate limit
        username_key = f"login_attempt:{username}"
        username_attempts = redis_conn.incr(username_key)
        if username_attempts == 1:
            redis_conn.expire(username_key, 3600)  # 1 hour TTL
        if username_attempts > 5:
            return True

        # Check IP rate limit
        ip_key = f"login_ip:{ip}"
        ip_attempts = redis_conn.incr(ip_key)
        if ip_attempts == 1:
            redis_conn.expire(ip_key, 3600)  # 1 hour TTL
        if ip_attempts > 20:
            return True

        return False
    except redis.RedisError as e:
        logger.error(f"Redis error in rate limiting: {str(e)}")
        # Fail open in case of Redis issues (don't block legitimate users)
        return False
    finally:
        redis_conn.close()

def reset_rate_limit(username: str, ip: str):
    """
    Reset rate limiting counters on successful login.
    """
    redis_conn = redis.Redis(connection_pool=redis_pool)
    try:
        redis_conn.delete(f"login_attempt:{username}")
        redis_conn.delete(f"login_ip:{ip}")
    except redis.RedisError as e:
        logger.error(f"Redis error resetting rate limits: {str(e)}")
    finally:
        redis_conn.close()

def log_failed_attempt(username: str, ip: str, user_agent: str, reason: str):
    """
    Log failed login attempts to Redis for security monitoring and analysis.
    Stores:
    - Timestamp
    - Username attempted
    - IP address
    - User agent
    - Failure reason
    """
    redis_conn = redis.Redis(connection_pool=redis_pool)
    try:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "username": username,
            "ip": ip,
            "user_agent": user_agent,
            "reason": reason
        }
        # Store in a Redis list with 30 day retention
        redis_conn.lpush("security:failed_logins", str(log_entry))
        redis_conn.ltrim("security:failed_logins", 0, 9999)  # Keep last 10,000 entries
    except redis.RedisError as e:
        logger.error(f"Redis error logging failed attempt: {str(e)}")
    finally:
        redis_conn.close()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Securely verify password with constant-time comparison."""
    return pwd_context.verify(plain_password, hashed_password)




@router.post("/signup/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """
    Create a new user with resident information.

    Checks:
    1. Phone number must be in AllowList
    2. Email must exist in Zoho contacts
    3. Contact must have an address in Zoho

    On success:
    - Creates user in database
    - Creates associated resident record
    - Returns the created user

    Raises appropriate HTTP exceptions for various failure cases.
    """
    logger.info(f"Attempting user creation for email: {user.email}")

    try:
        # Start transaction
        db.begin()

        # Validate phone number against allowlist
        db_allowlist = db.query(models.AllowList).filter(
            models.AllowList.phone_number == user.phone_number).first()

        if not db_allowlist:
            logger.warning(
                f"Phone number not in AllowList: {user.phone_number}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Phone number not authorized for registration.",
            )

        # Set default role if not provided
        if user.role_id is None:
            db_role = db.query(models.Role).filter(
                models.Role.name == "USER").first()
            if not db_role:
                logger.error("Default USER role not found in database")
                role =models.Role(name="USER", description="Default user role")
                db_role =crud.create_role(db, role)
            user.role_id = db_role.id
            logger.debug(f"Assigned default role ID: {user.role_id}")

        # Check for existing user with same email or phone
        existing_user = db.query(models.User).filter(
            (models.User.email == user.email) |
            (models.User.phone_number == user.phone_number)
        ).first()

        if existing_user:
            logger.warning(
                f"User already exists with email/phone: {user.email}/{user.phone_number}")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this email or phone number already exists",
            )

        # Create user record
        hashed_password = get_password_hash(user.password)
        db_user = models.User(
            email=user.email,
            phone_number=user.phone_number,
            role_id=user.role_id,
            hashed_password=hashed_password,
        )
        db.add(db_user)
        db.flush()  # Ensure we get the ID for resident creation

        logger.info("Fetching contact data from Zoho...")
        try:
            
            
            
            # Get Zoho contact information
            zoho_contacts = zoho_client.make_request("contacts")
            zoho_contact = find_contact_by_email(
                user.email, zoho_contacts['contacts'])

            if not zoho_contact:
                logger.error(f"Zoho contact not found for email: {user.email}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Email not found in our system. Please contact support.",
                )
            invoices_data = zoho_client.make_request("invoices")
            contact_invoices = find_invoices_by_email(user.email, invoices_data.get('invoices', []))
            delinquency_status = "ACTIVE" if count_inactive_status(contact_invoices, "overdue") >= 3 else "INACTIVE"
            # Get address information
            contact_address = zoho_client.make_request(
                f"contacts/{zoho_contact['contact_id']}/address")

            if not contact_address.get('addresses'):
                logger.error(
                    f"No address found for Zoho contact: {zoho_contact['contact_id']}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Address information missing for your account. Please contact support.",
                )

            # Create resident record
            resident_data = {
                "lot_no": contact_address['addresses'][0]['attention'],
                "status": "ACTIVE",
                "delinquency_status": delinquency_status,
                "user_id": db_user.id,
            }

            logger.info(
                f"Creating resident record for lot: {resident_data['lot_no']}")
            db_resident = models.Resident(**resident_data)
            db.add(db_resident)

            # Commit transaction
            db.commit()
            logger.info(
                f"Successfully created user {db_user.id} and resident {db_resident.id}")

            return db_user.to_dict()

        except HTTPException:
            # Re-raise HTTPExceptions from Zoho operations
            raise
        except Exception as zoho_error:
            logger.error(
                f"Zoho integration failed: {str(zoho_error)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Unable to verify account information. Please try again later.",
            )

    except HTTPException:
        # Re-raise HTTPExceptions we generated
        db.rollback()
        raise

    except Exception as unexpected_error:
        db.rollback()
        logger.critical(
            f"Unexpected error during user creation for {user.email}: {str(unexpected_error)}",
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during registration.",
        )


@router.get("/users/me", response_model=schemas.Contact)
def read_users_me(
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_db)
):
    """
    Get current authenticated user's details with Zoho contact information.
    
    Returns:
    - User details from database
    - Contact information from Zoho
    - Address information
    - Recent invoices (max 6, sorted by due date)
    
    Raises:
    - HTTP 401 for invalid/expired tokens
    - HTTP 404 if user/contact not found
    - HTTP 500 for unexpected errors
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        logger.info("Attempting to fetch current user details")
        
        # Validate and decode JWT token
        try:
            payload = jwt.decode(
                token, 
                settings.secret_key,
                algorithms=[settings.algorithm],
                options={"require": ["exp", "sub"]}  # Ensure required claims exist
            )
            email: str = payload.get("sub")
            if not email:
                logger.warning("Invalid token: missing 'sub' field")
                raise credentials_exception
        except JWTError as jwt_err:
            logger.warning(f"JWT validation failed: {str(jwt_err)}")
            raise credentials_exception

        # Fetch user from database
        user = crud.get_user_by_email(db, email=email)
        if not user:
            logger.warning(f"User not found for email: {email}")
            raise credentials_exception

        logger.debug(f"Fetching Zoho data for user: {email}")
        
        # Get Zoho contact information with error handling
        try:
            zoho_contacts = zoho_client.make_request("contacts")
            zoho_contact = find_contact_by_email(user.email, zoho_contacts.get('contacts', []))
            
            if not zoho_contact:
                logger.error(f"Zoho contact not found for email: {user.email}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Contact information not found"
                )

            # Parallelize these requests when possible
            contact_address, contact_invoices = get_zoho_supplementary_data(
                zoho_contact['contact_id'],
                user.email
            )

            # Prepare response data
            response_data = {
                **zoho_contact,
                "address": contact_address,
                "invoices": contact_invoices,
                "user_id": user.id,
                "role": user.role.name if user.role else None  # Add role info
            }

            logger.info(f"Successfully fetched details for user: {email}")
            return response_data

        except HTTPException:
            raise
        except Exception as zoho_error:
            logger.error(f"Zoho integration error: {str(zoho_error)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Unable to fetch contact information. Please try again later."
            )

    except HTTPException:
        raise  # Re-raise handled exceptions
    except Exception as unexpected_error:
        logger.critical(
            f"Unexpected error in /users/me: {str(unexpected_error)}",
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while processing your request"
        )


def get_zoho_supplementary_data(contact_id: str, email: str) -> tuple:
    """Fetch address and invoices data from Zoho with error handling"""
    try:
        # Get address
        address_data = zoho_client.make_request(f"contacts/{contact_id}/address")
        addresses = address_data.get('addresses', [])
        if not addresses:
            logger.warning(f"No address found for contact: {contact_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Address information not found"
            )

        # Get invoices
        invoices_data = zoho_client.make_request("invoices")
        contact_invoices = find_invoices_by_email(email, invoices_data.get('invoices', []))
        
        return addresses[0], contact_invoices
        
    except Exception as e:
        logger.error(f"Failed to get supplementary Zoho data: {str(e)}")
        raise


def find_contact_by_email(email: str, contacts: list) -> Optional[dict]:
    """Find contact by email with case-insensitive comparison"""
    if not contacts:
        return None
        
    return next(
        (contact for contact in contacts 
         if contact.get('email', '').lower() == email.lower()),
        None
    )


def find_invoices_by_email(email: str, invoices: list) -> list:
    """Find and sort invoices by email with validation"""
    if not invoices:
        return []
    
    try:
        valid_invoices = [
            inv for inv in invoices 
            if inv.get('email', '').lower() == email.lower()
            and inv.get('due_date') is not None
        ]
        
        # Sort by due_date descending and return max 6 invoices
        return sorted(
            valid_invoices,
            key=lambda x: x['due_date'],
            reverse=True
        )[:6]
        
    except Exception as e:
        logger.error(f"Error processing invoices: {str(e)}")
        return []
    
@router.post("/refresh", response_model=schemas.Token)
async def refresh_token(token_data: schemas.TokenRefresh):
    payload = verify_refresh_token(token_data.refresh_token)
    new_access_token = create_access_token(
        data={"sub": payload.get("sub")},
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes)
    )
    
    return {
        "access_token": new_access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.access_token_expire_minutes * 60
    }
    
    
def count_inactive_status(json_list,status):
    """
    Counts the occurrences of 'inactive' status in a JSON list of dictionaries.

    Args:
        json_list: A list of dictionaries in JSON format, each containing a 'status' key.
        
    Returns:
        The count of inactive statuses (0 if none found).
    """
    try:
        # If input is a JSON string, parse it first
        if isinstance(json_list, str):
            data = json.loads(json_list)
        else:
            data = json_list
            
        # Count inactive statuses
        inactive_count = sum(1 for item in data 
                            if isinstance(item, dict) 
                            and item.get('status') == status)
        
        return inactive_count

    except (json.JSONDecodeError, AttributeError, TypeError) as e:
        print(f"Error processing JSON data: {e}")
        return 0
    
    
@router.post("/logout")
async def logout(
    token: str = Depends(oauth2_scheme),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """
    Logout endpoint that invalidates the current access token.
    
    Steps:
    1. Validates the incoming token
    2. Adds token to a blacklist with remaining TTL
    3. Logs the logout event
    4. Returns successful logout response
    
    Security Considerations:
    - Uses Redis for token blacklisting
    - Logs client information for security monitoring
    - Handles token validation errors gracefully
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Get client information for logging
        client_ip = request.client.host if request else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        
        # Validate token
        try:
            payload = jwt.decode(
                token, 
                settings.secret_key,
                algorithms=[settings.algorithm]
            )
            email = payload.get("sub")
            exp = payload.get("exp")
            
            if not email:
                logger.warning("Invalid token: missing email in payload")
                raise credentials_exception
                
            # Calculate remaining token TTL
            if exp:
                remaining_ttl = exp - int(time.time())
                if remaining_ttl < 0:
                    remaining_ttl = 0
            else:
                remaining_ttl = settings.access_token_expire_minutes * 60
                
        except JWTError as e:
            logger.warning(f"JWT validation failed during logout: {str(e)}")
            raise credentials_exception
            
        # Add token to blacklist
        redis_conn = redis.Redis(connection_pool=redis_pool)
        try:
            # Store token with remaining TTL
            redis_conn.setex(
                f"token_blacklist:{token}",
                remaining_ttl,
                "invalidated"
            )
            
            # Log the logout event
            logout_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "user": email,
                "ip": client_ip,
                "user_agent": user_agent,
                "action": "logout"
            }
            redis_conn.lpush("security:user_logouts", json.dumps(logout_entry))
            redis_conn.ltrim("security:user_logouts", 0, 9999)
            
        except redis.RedisError as e:
            logger.error(f"Redis error during logout: {str(e)}")
            # Continue even if Redis fails - don't block logout
        finally:
            redis_conn.close()
            
        logger.info(
            f"User {email} logged out successfully from {client_ip}",
            extra={
                "tags": {
                    "action": "logout",
                    "user": email,
                    "ip": client_ip
                }
            }
        )
        
        return {"detail": "Successfully logged out"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Unexpected error during logout: {str(e)}",
            exc_info=True,
            extra={"tags": {"error": "logout_failure", "severity": "high"}}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during logout"
        )
        
async def is_token_blacklisted(token: str) -> bool:
    """Check if token is in the blacklist"""
    redis_conn = redis.Redis(connection_pool=redis_pool)
    try:
        return redis_conn.exists(f"token_blacklist:{token}") == 1
    except redis.RedisError as e:
        logger.error(f"Redis error checking token blacklist: {str(e)}")
        return False
    finally:
        redis_conn.close()
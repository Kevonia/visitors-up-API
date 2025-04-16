import logging
from app.zoho_integration.zoho_client import ZohoClient
from fastapi import FastAPI, Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from .. import crud, schemas
from ..utilities.db_util import get_db
from app.config.config import settings
from ..utilities.authutil import verify_password, create_access_token
from jose import JWTError, jwt
from app.logging_config import logger
from aiocache import cached

router = APIRouter()
zoho_client = ZohoClient()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login")
# Protected routes with authentication and caching
cache_timer = 3600
user_test="kereeseholness@gmail.com"
@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    try:
        logger.info(f"Login attempt for user: {form_data.username}")

        # Fetch user from the database
        user = crud.get_user_by_email(db, email=form_data.username)
        if not user:
            logger.warning(f"User not found: {form_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
       
        # Verify password
        if not verify_password(form_data.password, user.hashed_password):
            logger.warning(f"Incorrect password for user: {form_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Generate access token
        access_token = create_access_token(data={"sub": user.email})
        logger.info(f"Login successful for user: {form_data.username}")
        return {"access_token": access_token, "token_type": "bearer"}

    except Exception as e:
        logger.error(f"Error during login for user {form_data.username}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during login",
        )

# Create a new user
@router.post("/signup/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db) ):
    return crud.create_user(db=db, user=user)

@router.get("/users/me", response_model=schemas.Contact)
# @cached(ttl=cache_timer)
def read_users_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        logger.info("Attempting to fetch current user details")

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

        logger.info(f"Successfully fetched details for user: {email}")
        zoho_contacts= zoho_client.make_request("contacts")
        zoho_invoices=zoho_client.make_request("invoices") 
        zoho_contact = find_contact_by_email(user_test,zoho_contacts['contacts'])  
        contact_address  = zoho_client.make_request(f"contacts/{zoho_contact['contact_id']}/address")
        contact_invoices= find_invoices_by_email(user_test,zoho_invoices['invoices'])
         
        zoho_contact['address']=contact_address['addresses'][0]
        zoho_contact['invoices']=contact_invoices
        return zoho_contact

    except JWTError as e:
        logger.error(f"JWT error while decoding token: {str(e)}", exc_info=True)
        raise credentials_exception
    except Exception as e:
        logger.error(f"Unexpected error while fetching user details: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while fetching user details",
        )
        
def find_contact_by_email(email, contacts):
    for contact in contacts:
        if contact.get('email') == email:
            return contact
    return None  

def find_invoices_by_email(email, invoices):
    invoicelist = [] 
    for invoice in invoices:
        if invoice.get('email') == email:
            invoicelist.append(invoice)
        invoicelist.sort(key=lambda x: x.get('due_date'), reverse=True)

    return invoicelist[:6]  # Return the first 6 invoices     
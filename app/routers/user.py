from typing import Optional
from app.routers.auth import find_contact_by_email
from app.zoho_integration.zoho_client import ZohoClient
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import schemas, crud
from ..utilities.db_util import get_db
from ..config.auth import get_current_user 
from aiocache import cached

router = APIRouter()
zoho_client = ZohoClient()
# Create a new user
@router.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db) , current_user: schemas.UserBase = Depends(get_current_user)):
    return crud.create_user(db=db, user=user)

# Get a user by ID
@router.get("/users/{user_id}", response_model=schemas.User)
def read_user(user_id: str, db: Session = Depends(get_db) , current_user: schemas.UserBase = Depends(get_current_user)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

@router.get("/users/{user_id}/invoices", response_model=list[schemas.Invoice])
def read_user(user_id: str, db: Session = Depends(get_db) , current_user: schemas.UserBase = Depends(get_current_user)):
    db_user = crud.get_user(db, user_id=user_id)
    zoho_contacts=zoho_client.make_request("contacts") 
    contact_invoices= find_contact_by_email(current_user.email,zoho_invoices['contacts'])
    zoho_invoices =zoho_client.make_request(f"invoices?customer_id={contact_invoices['contact_id']}")
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return contact_invoices
# Get all users
@router.get("/users/", response_model=list[schemas.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    users=crud.get_users(db, skip=skip, limit=limit)
    zoho_contacts = zoho_client.make_request("contacts")
    for user in users:
     zoho_contact = find_contact_by_email(user['email'], zoho_contacts.get('contacts', []))
     user['contact'] = zoho_contact
    return  users

# Update a user
@router.put("/users/{user_id}", response_model=schemas.User)
def update_user(user_id: str, user: schemas.UserUpdate, db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    db_user = crud.update_user(db, user_id=user_id, user=user)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

# Delete a user
@router.delete("/users/{user_id}", response_model=schemas.User)
def delete_user(user_id: str, db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    db_user = crud.delete_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user



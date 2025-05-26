# app/routers/allowlist.py
import re
from ..decorator.auth_decorator import admin_required
from fastapi import APIRouter, Depends, HTTPException,File, UploadFile
from sqlalchemy.orm import Session
from .. import schemas, crud
import pandas as pd
from ..utilities.db_util import get_db 
from ..config.auth import get_current_user 
from app.zoho_integration.zoho_client import ZohoClient
from aiocache import cached

router = APIRouter()
zoho_client = ZohoClient()
cache_timer =60

# Create a new allowlist entry
@router.post("/allowlist/")
@cached(ttl=cache_timer)
@admin_required
def create_allowlist(allowlist: schemas.AllowListCreate, db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    return crud.create_allowlist(db=db, allowlist=allowlist)

@router.post("/allowlist/file")
@admin_required
async def upload_csv(file: UploadFile = File(...), db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="File must be a CSV")

    # Read the CSV file into a pandas DataFrame
    try:
        df = pd.read_csv(file.file)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading CSV file: {str(e)}")

    # Validate the CSV columns
    required_columns = {"email", "phone_number"}
    if not required_columns.issubset(df.columns):
        raise HTTPException(status_code=400, detail=f"CSV must contain the following columns: {required_columns}")

    # Insert data into the database
    try:
        for _, row in df.iterrows():
            allow_list_entry = schemas.AllowListCreate(
                email=row["email"],
                phone_number=row["phone_number"]
            ) 
            crud.create_allowlist(db=db, allowlist=allow_list_entry)
    except Exception as e:
        # db.rollback()
        raise HTTPException(status_code=500, detail=f"Error inserting data into the database: {str(e)}")

    return {"message": "CSV data uploaded and inserted successfully"}


# Get an allowlist entry by ID
@router.get("/allowlist/load")
@admin_required
def load_allowlist(db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    crud.delete_all_allowlist(db)  # Clear existing allowlist entries
    zoho_contacts=zoho_client.make_request("contacts") 
    contacts_mobile_email = get_contacts_mobile_and_email(zoho_contacts)
    try:
        for contact in contacts_mobile_email:
            if len(contact["mobile"]) != 0 and len(contact["email"]) != 0:
                allow_list_entry = schemas.AllowListCreate(
                    email=contact["email"],
                    phone_number= clean_phone_number(contact["mobile"])
                ) 
                crud.create_allowlist(db=db, allowlist=allow_list_entry)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error inserting data into the database: {str(e)}")
    return {"message": "Allow list data updated  successfully"}

# Get an allowlist entry by ID
@router.get("/allowlist/{allowlist_id}", response_model=schemas.AllowList)
@admin_required
def read_allowlist(allowlist_id: str, db: Session = Depends(get_db),current_user: schemas.UserBase = Depends(get_current_user)):
    db_allowlist = crud.get_allowlist(db, allowlist_id=allowlist_id)
    if db_allowlist is None:
        raise HTTPException(status_code=404, detail="AllowList entry not found")
    return db_allowlist

# Get all allowlist entries
@router.get("/allowlist/", response_model=list[schemas.AllowList])
@cached(ttl=cache_timer)
def read_all_allowlists(skip: int = 0, limit: int = 100, db: Session = Depends(get_db) , current_user: schemas.UserBase = Depends(get_current_user)):
    return crud.get_all_allowlists(db, skip=skip, limit=limit)

# Update an allowlist entry
@router.put("/allowlist/{allowlist_id}", response_model=schemas.AllowList)
@admin_required
def update_allowlist(allowlist_id: str, allowlist: schemas.AllowListUpdate, db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    db_allowlist = crud.update_allowlist(db, allowlist_id=allowlist_id, allowlist=allowlist)
    if db_allowlist is None:
        raise HTTPException(status_code=404, detail="AllowList entry not found")
    return db_allowlist

# Delete an allowlist entry
@router.delete("/allowlist/{allowlist_id}", response_model=schemas.AllowList)
@admin_required
def delete_allowlist(allowlist_id: str, db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    db_allowlist = crud.delete_allowlist(db, allowlist_id=allowlist_id)
    if db_allowlist is None:
        raise HTTPException(status_code=404, detail="AllowList entry not found")
    return db_allowlist


def get_contacts_mobile_and_email(json_data):
    """
    Extracts mobile numbers and emails from all contacts.
    
    Args:
        json_data (dict): JSON data containing contacts.
        
    Returns:
        list: A list of dictionaries, each containing 'mobile' and 'email' for a contact.
    """
    contacts_info = []
    
    if 'contacts' in json_data and isinstance(json_data['contacts'], list):
        for contact in json_data['contacts']:
            mobile = contact.get('mobile', 'N/A')  # Default 'N/A' if missing
            email = contact.get('email', 'N/A')    # Default 'N/A' if missing
            contacts_info.append({"mobile": mobile, "email": email})
    
    return contacts_info


def clean_phone_number(phone):
    """Removes all non-digit characters from a phone number."""
    return re.sub(r'\D', '', phone) 
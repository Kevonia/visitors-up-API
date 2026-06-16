# app/routers/allowlist.py
# from ..decorator.auth_decorator import admin_required
from fastapi import APIRouter, Depends, HTTPException,File, UploadFile
from sqlalchemy.orm import Session
from .. import schemas, crud
import pandas as pd
from ..utilities.db_util import get_db
from ..config.auth import get_current_user
from ..zoho_integration.zoho_client import ZohoClient
from ..logging_config import logger
router = APIRouter()

zoho_client = ZohoClient()


def _fetch_zoho_contacts() -> list:
    """Pull every Zoho contact (paged, 200 at a time)."""
    contacts, page = [], 1
    while True:
        data = zoho_client.make_request("contacts", params={"page": page, "per_page": 200})
        contacts.extend(data.get("contacts", []))
        if not data.get("page_context", {}).get("has_more_page"):
            break
        page += 1
    return contacts


# Resync the allowlist from Zoho contacts (additive — never deletes existing rows)
@router.post("/allowlist/sync-zoho")
def sync_allowlist_from_zoho(db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    try:
        contacts = _fetch_zoho_contacts()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Zoho contact fetch failed during allowlist sync: {e}")
        raise HTTPException(status_code=502, detail="Could not reach Zoho to fetch contacts.")
    return crud.sync_allowlist_from_contacts(db, contacts)

# Create a new allowlist entry
@router.post("/allowlist/")
# @admin_required
def create_allowlist(allowlist: schemas.AllowListCreate, db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    return crud.create_allowlist(db=db, allowlist=allowlist)

@router.post("/allowlist/file")
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
@router.get("/allowlist/{allowlist_id}", response_model=schemas.AllowList)
def read_allowlist(allowlist_id: str, db: Session = Depends(get_db),current_user: schemas.UserBase = Depends(get_current_user)):
    db_allowlist = crud.get_allowlist(db, allowlist_id=allowlist_id)
    if db_allowlist is None:
        raise HTTPException(status_code=404, detail="AllowList entry not found")
    return db_allowlist

# Get all allowlist entries
@router.get("/allowlist/", response_model=list[schemas.AllowList])
def read_all_allowlists(skip: int = 0, limit: int = 100, db: Session = Depends(get_db) , current_user: schemas.UserBase = Depends(get_current_user)):
    return crud.get_all_allowlists(db, skip=skip, limit=limit)

# Update an allowlist entry
@router.put("/allowlist/{allowlist_id}", response_model=schemas.AllowList)
def update_allowlist(allowlist_id: str, allowlist: schemas.AllowListUpdate, db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    db_allowlist = crud.update_allowlist(db, allowlist_id=allowlist_id, allowlist=allowlist)
    if db_allowlist is None:
        raise HTTPException(status_code=404, detail="AllowList entry not found")
    return db_allowlist

# Delete an allowlist entry
@router.delete("/allowlist/{allowlist_id}", response_model=schemas.AllowList)
def delete_allowlist(allowlist_id: str, db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    db_allowlist = crud.delete_allowlist(db, allowlist_id=allowlist_id)
    if db_allowlist is None:
        raise HTTPException(status_code=404, detail="AllowList entry not found")
    return db_allowlist
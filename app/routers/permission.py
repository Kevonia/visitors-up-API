from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import schemas, crud
from ..database import SessionLocal
from ..utilities.db_util import get_db
from ..config.auth import get_current_user 
router = APIRouter()


# Create a new permission
@router.post("/permissions/", response_model=schemas.Permission)
def create_permission(permission: schemas.PermissionCreate, db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    return crud.create_permission(db=db, permission=permission)

# Get a permission by ID
@router.get("/permissions/{permission_id}", response_model=schemas.Permission)
def read_permission(permission_id: str, db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    db_permission = crud.get_permission(db, permission_id=permission_id)
    if db_permission is None:
        raise HTTPException(status_code=404, detail="Permission not found")
    return db_permission

# Get all permissions
@router.get("/permissions/", response_model=list[schemas.Permission])
def read_permissions(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    return crud.get_permissions(db, skip=skip, limit=limit)

# Update a permission
@router.put("/permissions/{permission_id}", response_model=schemas.Permission)
def update_permission(permission_id: str, permission: schemas.PermissionUpdate, db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    db_permission = crud.update_permission(db, permission_id=permission_id, permission=permission)
    if db_permission is None:
        raise HTTPException(status_code=404, detail="Permission not found")
    return db_permission

# Delete a permission
@router.delete("/permissions/{permission_id}", response_model=schemas.Permission)
def delete_permission(permission_id: str, db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    db_permission = crud.delete_permission(db, permission_id=permission_id)
    if db_permission is None:
        raise HTTPException(status_code=404, detail="Permission not found")
    return db_permission
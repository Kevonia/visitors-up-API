from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import  schemas, crud
from ..utilities.db_util import get_db
from ..config.auth import get_current_user 
router = APIRouter()



# Create a new role
@router.post("/roles/", response_model=schemas.Role)
def create_role(role: schemas.RoleCreate, db: Session = Depends(get_db) , current_user: schemas.UserBase = Depends(get_current_user)):
    return crud.create_role(db=db, role=role)

# Get a role by ID
@router.get("/roles/{role_id}", response_model=schemas.Role)
def read_role(role_id: str, db: Session = Depends(get_db) , current_user: schemas.UserBase = Depends(get_current_user)):
    db_role = crud.get_role(db, role_id=role_id)
    if db_role is None:
        raise HTTPException(status_code=404, detail="Role not found")
    return db_role

# Get all roles
@router.get("/roles/", response_model=list[schemas.Role])
def read_roles(skip: int = 0, limit: int = 100, db: Session = Depends(get_db) , current_user: schemas.UserBase = Depends(get_current_user)) :
    return crud.get_roles(db, skip=skip, limit=limit)

# Update a role
@router.put("/roles/{role_id}", response_model=schemas.Role)
def update_role(role_id: str, role: schemas.RoleUpdate, db: Session = Depends(get_db) , current_user: schemas.UserBase = Depends(get_current_user)):
    db_role = crud.update_role(db, role_id=role_id, role=role)
    if db_role is None:
        raise HTTPException(status_code=404, detail="Role not found")
    return db_role

# Delete a role
@router.delete("/roles/{role_id}", response_model=schemas.Role)
def delete_role(role_id: str, db: Session = Depends(get_db) , current_user: schemas.UserBase = Depends(get_current_user)) :
    db_role = crud.delete_role(db, role_id=role_id)
    if db_role is None:
        raise HTTPException(status_code=404, detail="Role not found")
    return db_role
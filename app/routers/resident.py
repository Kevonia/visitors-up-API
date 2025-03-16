from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import models, schemas, crud
from ..database import SessionLocal

router = APIRouter()

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Create a new resident
@router.post("/residents/", response_model=schemas.Resident)
def create_resident(resident: schemas.ResidentCreate, db: Session = Depends(get_db)):
    return crud.create_resident(db=db, resident=resident)

# Get a resident by ID
@router.get("/residents/{resident_id}", response_model=schemas.Resident)
def read_resident(resident_id: str, db: Session = Depends(get_db)):
    db_resident = crud.get_resident(db, resident_id=resident_id)
    if db_resident is None:
        raise HTTPException(status_code=404, detail="Resident not found")
    return db_resident

# Get all residents
@router.get("/residents/", response_model=list[schemas.Resident])
def read_residents(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return crud.get_residents(db, skip=skip, limit=limit)

# Update a resident
@router.put("/residents/{resident_id}", response_model=schemas.Resident)
def update_resident(resident_id: str, resident: schemas.ResidentUpdate, db: Session = Depends(get_db)):
    db_resident = crud.update_resident(db, resident_id=resident_id, resident=resident)
    if db_resident is None:
        raise HTTPException(status_code=404, detail="Resident not found")
    return db_resident

# Delete a resident
@router.delete("/residents/{resident_id}", response_model=schemas.Resident)
def delete_resident(resident_id: str, db: Session = Depends(get_db)):
    db_resident = crud.delete_resident(db, resident_id=resident_id)
    if db_resident is None:
        raise HTTPException(status_code=404, detail="Resident not found")
    return db_resident
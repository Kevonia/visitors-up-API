# app/routers/visitor.py
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

# Create a new visitor
@router.post("/visitors/", response_model=schemas.Visitor)
def create_visitor(visitor: schemas.VisitorCreate, db: Session = Depends(get_db)):
    return crud.create_visitor(db=db, visitor=visitor)

# Get a visitor by ID
@router.get("/visitors/{visitor_id}", response_model=schemas.Visitor)
def read_visitor(visitor_id: str, db: Session = Depends(get_db)):
    db_visitor = crud.get_visitor(db, visitor_id=visitor_id)
    if db_visitor is None:
        raise HTTPException(status_code=404, detail="Visitor not found")
    return db_visitor

# Get all visitors
@router.get("/visitors/", response_model=list[schemas.Visitor])
def read_visitors(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return crud.get_visitors(db, skip=skip, limit=limit)

# Update a visitor
@router.put("/visitors/{visitor_id}", response_model=schemas.Visitor)
def update_visitor(visitor_id: str, visitor: schemas.VisitorUpdate, db: Session = Depends(get_db)):
    db_visitor = crud.update_visitor(db, visitor_id=visitor_id, visitor=visitor)
    if db_visitor is None:
        raise HTTPException(status_code=404, detail="Visitor not found")
    return db_visitor

# Delete a visitor
@router.delete("/visitors/{visitor_id}", response_model=schemas.Visitor)
def delete_visitor(visitor_id: str, db: Session = Depends(get_db)):
    db_visitor = crud.delete_visitor(db, visitor_id=visitor_id)
    if db_visitor is None:
        raise HTTPException(status_code=404, detail="Visitor not found")
    return db_visitor
# app/routers/visitor.py
from app import models
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import schemas, crud
from ..utilities.db_util import get_db
from ..config.auth import get_current_user
from aiocache import cached
from ..logging_config import logger
router = APIRouter()


# Get all visitors of the logged in users
@router.get("/visitors/", response_model=list[schemas.Visitor])
def read_visitors(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: schemas.UserBase = Depends(get_current_user)):
    user = crud.get_user_by_email(db, email=current_user.email)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.resident is None:
        raise HTTPException(status_code=404, detail="Resident not found")

    visitor = crud.get_visitors_by_resident(
        db, user.resident.id, skip=skip, limit=limit)
    if visitor is None:
        raise HTTPException(status_code=404, detail="Visitor not found")
    return visitor

# Create a new visitors  visitors of the logged in users


@router.post("/visitors/", response_model=schemas.Visitor)
def create_visitor(
    visitor: schemas.VisitorCreate, 
    db: Session = Depends(get_db), 
    current_user: schemas.UserBase = Depends(get_current_user)
) -> schemas.Visitor:
    """
    Create a new visitor associated with the current user.
    
    Args:
        visitor: Visitor data to create
        db: Database session
        current_user: Authenticated user
        
    Returns:
        The created visitor record
        
    Raises:
        HTTPException: If user not found or other error occurs
    """
    user = crud.get_user_by_email(db, email=current_user.email)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if not hasattr(user, 'resident') or user.resident is None:
        raise HTTPException(status_code=400, detail="User is not associated with a resident")
    
    visitor_data = models.Visitor(
        name=visitor.name,
        relationship_type=visitor.relationship_type,
        created_by=user.resident.id,
    ) 
    logger.info(f"Creating visitor: {user.resident}")
       # Check delinquency status
    if user.resident.delinquency_status == models.DelinquencyEnum.ACTIVE:
        raise HTTPException(
            status_code=403,
            detail="Cannot add more visitors. Your account has delinquency issues. Please contact admin."
        )
    try:
        return crud.create_visitor(db=db, visitor=visitor_data)
    except Exception as e:
        raise HTTPException(
            status_code=400, 
            detail=f"Error creating visitor: {str(e)}"
        )
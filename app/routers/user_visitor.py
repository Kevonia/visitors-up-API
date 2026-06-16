# app/routers/visitor.py
from app import models
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import schemas, crud
from ..utilities.db_util import get_db
from ..config.auth import get_current_user
from ..realtime import publish_event
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

    logger.info(f"Creating visitor: {user.resident}")
       # Check delinquency status
    if user.resident.delinquency_status == models.DelinquencyEnum.ACTIVE:
        raise HTTPException(
            status_code=403,
            detail="Cannot add more visitors. Your account has delinquency issues. Please contact admin."
        )

    # Force ownership to the authenticated resident regardless of payload.
    visitor.created_by = str(user.resident.id)
    try:
        created = crud.create_visitor(db=db, visitor=visitor)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Error creating visitor: {str(e)}"
        )

    # Notify any connected guard apps so the new registration shows up live in
    # the gate app. Best-effort: a Redis hiccup must not fail the creation.
    # Only the id is broadcast — the guard app re-fetches details over its
    # authenticated connection, so no visitor/resident PII transits pub/sub.
    publish_event("visitor.created", {"id": created.get("id")})
    return created


def _owned_visitor_or_404(db: Session, visitor_id: str, current_user):
    """Fetch a visitor and assert it belongs to the authenticated resident."""
    user = crud.get_user_by_email(db, email=current_user.email)
    if user is None or user.resident is None:
        raise HTTPException(status_code=404, detail="Resident not found")
    db_visitor = db.query(models.Visitor).filter(models.Visitor.id == visitor_id).first()
    if db_visitor is None:
        raise HTTPException(status_code=404, detail="Visitor not found")
    if str(db_visitor.created_by) != str(user.resident.id):
        raise HTTPException(status_code=403, detail="This visitor does not belong to you.")
    return db_visitor


# Update one of the current resident's own visitors
@router.put("/visitors/{visitor_id}", response_model=schemas.Visitor)
def update_my_visitor(
    visitor_id: str,
    visitor: schemas.VisitorUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.UserBase = Depends(get_current_user),
):
    _owned_visitor_or_404(db, visitor_id, current_user)
    # Residents cannot reassign ownership.
    visitor.created_by = None
    return crud.update_visitor(db, visitor_id=visitor_id, visitor=visitor)


# Delete one of the current resident's own visitors
@router.delete("/visitors/{visitor_id}", response_model=schemas.Visitor)
def delete_my_visitor(
    visitor_id: str,
    db: Session = Depends(get_db),
    current_user: schemas.UserBase = Depends(get_current_user),
):
    _owned_visitor_or_404(db, visitor_id, current_user)
    return crud.delete_visitor(db, visitor_id=visitor_id)
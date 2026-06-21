"""Public (no-auth) pre-registration pass lookup.

A resident shares a link (e.g. via WhatsApp) containing a visitor's share_token;
the guest opens it to see their gate pass — no app/login needed. The QR the guard
scans is still the visitor id, so the existing gate scan flow is unchanged.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..utilities.db_util import get_db

router = APIRouter()


@router.get("/passes/{share_token}", response_model=schemas.PublicPass)
def public_pass(share_token: str, db: Session = Depends(get_db)):
    v = (
        db.query(models.Visitor)
        .filter(models.Visitor.share_token == share_token)
        .first()
    )
    if not v:
        raise HTTPException(status_code=404, detail="Pass not found")
    return {
        "id": str(v.id),
        "name": v.name,
        "relationship_type": v.relationship_type,
        "visit_type": v.visit_type.value if v.visit_type else None,
        "status": v.effective_status().value,
        "lot_no": v.created_by_user.lot_no if v.created_by_user else None,
        "resident_name": v.created_by_user.name if v.created_by_user else None,
        "valid_from": v.valid_from,
        "valid_until": v.valid_until,
    }

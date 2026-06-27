"""Resident maintenance / "Report Issue" requests, tracked to resolution.

Residents file requests; admins/managers see all and update status (which
notifies the resident). Mirrors the incident flow.
"""
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc
from sqlalchemy.orm import Session

from .. import models, schemas, crud, push
from ..realtime import publish_event
from ..utilities.db_util import get_db
from ..config.auth import get_current_user, require_roles
from ..enums import RoleEnum
from ..logging_config import logger

router = APIRouter()

manager = require_roles(RoleEnum.ADMIN.value, RoleEnum.MANAGER.value)
# Guards/managers/admins may *view* requests in the security app (read-only).
staff = require_roles(RoleEnum.SECURITY.value, RoleEnum.ADMIN.value, RoleEnum.MANAGER.value)
_VALID_STATUS = {"OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"}


@router.post("/user/maintenance", response_model=schemas.MaintenanceOut)
def create_request(
    payload: schemas.MaintenanceCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """A resident reports an issue."""
    user = crud.get_user_by_email(db, email=current_user.email)
    resident = user.resident if user else None
    now = int(time.time())
    req = models.MaintenanceRequest(
        resident_id=resident.id if resident else None,
        reporter_user_id=user.id if user else None,
        lot_no=resident.lot_no if resident else None,
        category=(payload.category or "general"),
        title=payload.title,
        description=payload.description,
        priority=(payload.priority or "normal"),
        status="OPEN",
        created_at=now,
        updated_at=now,
    )
    db.add(req)
    db.commit()
    db.refresh(req)

    # Notify admins/managers (best-effort).
    try:
        push.send_to_tokens(
            push.tokens_for_guards(db),  # SECURITY/ADMIN/MANAGER
            "New maintenance request",
            f"{req.title} (Lot {req.lot_no or '—'})",
            data={"type": "maintenance.created", "id": str(req.id)},
        )
    except Exception as e:
        logger.warning(f"FCM maintenance push failed: {e}")
    return req.to_dict()


@router.get("/user/maintenance", response_model=list[schemas.MaintenanceOut])
def my_requests(
    db: Session = Depends(get_db), current_user=Depends(get_current_user),
):
    """The current resident's own requests, newest first."""
    user = crud.get_user_by_email(db, email=current_user.email)
    if not user or not user.resident:
        return []
    rows = (
        db.query(models.MaintenanceRequest)
        .filter(models.MaintenanceRequest.resident_id == user.resident.id)
        .order_by(desc(models.MaintenanceRequest.created_at))
        .all()
    )
    return [r.to_dict() for r in rows]


@router.get("/admin/maintenance", response_model=list[schemas.MaintenanceOut])
def all_requests(
    status: Optional[str] = None,
    limit: int = 200,
    db: Session = Depends(get_db),
    _user=Depends(manager),
):
    """All requests (admin/manager), newest first; optional status filter."""
    q = db.query(models.MaintenanceRequest)
    if status:
        q = q.filter(models.MaintenanceRequest.status == status.upper())
    rows = q.order_by(desc(models.MaintenanceRequest.created_at)).limit(limit).all()
    return [r.to_dict() for r in rows]


@router.get("/staff/maintenance", response_model=list[schemas.MaintenanceOut])
def staff_requests(
    status: Optional[str] = None,
    limit: int = 200,
    db: Session = Depends(get_db),
    _user=Depends(staff),
):
    """Read-only list for the security app (guards/managers), newest first."""
    q = db.query(models.MaintenanceRequest)
    if status:
        q = q.filter(models.MaintenanceRequest.status == status.upper())
    rows = q.order_by(desc(models.MaintenanceRequest.created_at)).limit(min(limit, 500)).all()
    return [r.to_dict() for r in rows]


@router.post("/admin/maintenance/{request_id}/status",
             response_model=schemas.MaintenanceOut)
def update_status(
    request_id: str,
    payload: schemas.MaintenanceStatusUpdate,
    db: Session = Depends(get_db),
    _user=Depends(manager),
):
    status = (payload.status or "").upper()
    if status not in _VALID_STATUS:
        raise HTTPException(status_code=422, detail="Invalid status")
    req = (db.query(models.MaintenanceRequest)
           .filter(models.MaintenanceRequest.id == request_id).first())
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")
    req.status = status
    req.updated_at = int(time.time())
    db.commit()
    db.refresh(req)

    # Notify the resident their request moved (best-effort).
    try:
        if req.reporter_user_id:
            tokens = push.tokens_for_user(db, str(req.reporter_user_id))
            push.send_to_tokens(
                tokens, "Maintenance update",
                f"'{req.title}' is now {status.replace('_', ' ').title()}",
                data={"type": "maintenance.updated", "id": str(req.id)},
            )
    except Exception as e:
        logger.warning(f"FCM maintenance status push failed: {e}")
    return req.to_dict()

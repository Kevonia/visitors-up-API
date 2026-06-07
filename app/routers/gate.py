# app/routers/gate.py
"""Gate operations for security guards (and admins): manual visitor lookup,
logging arrivals/departures, and the audited gate log."""
import time
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import or_, desc
from sqlalchemy.orm import Session

from .. import models, schemas
from ..enums import RoleEnum, VisitType, VisitorStatus
from ..utilities.db_util import get_db
from ..config.auth import require_roles
from ..config.config import settings
from ..notifications.service import notify_guest_movement
from ..logging_config import logger

router = APIRouter()

# Guards, managers and admins may operate the gate.
gate_user = require_roles(RoleEnum.SECURITY.value, RoleEnum.ADMIN.value, RoleEnum.MANAGER.value)


@router.get("/visitors/search", response_model=list[schemas.GateVisitorSearchResult])
def search_visitors(
    q: Optional[str] = Query(None, description="Name, phone or vehicle plate"),
    lot_no: Optional[str] = Query(None, description="Resident lot number"),
    limit: int = 50,
    db: Session = Depends(get_db),
    _user=Depends(gate_user),
):
    """Manual lookup: find registered visitors across residents so a guard can
    confirm a caller before logging entry."""
    query = db.query(models.Visitor).join(
        models.Resident, models.Visitor.created_by == models.Resident.id
    )

    if q:
        like = f"%{q.strip()}%"
        query = query.filter(
            or_(
                models.Visitor.name.ilike(like),
                models.Visitor.phone.ilike(like),
                models.Visitor.vehicle_plate.ilike(like),
            )
        )
    if lot_no:
        query = query.filter(models.Resident.lot_no.ilike(f"%{lot_no.strip()}%"))

    visitors = query.order_by(models.Visitor.name).limit(limit).all()

    results = []
    for v in visitors:
        results.append({
            "id": str(v.id),
            "name": v.name,
            "relationship_type": v.relationship_type,
            "visit_type": v.visit_type.value if v.visit_type else None,
            "status": v.effective_status().value,
            "valid_from": v.valid_from,
            "valid_until": v.valid_until,
            "phone": v.phone,
            "vehicle_plate": v.vehicle_plate,
            "lot_no": v.created_by_user.lot_no if v.created_by_user else None,
            "resident_id": str(v.created_by) if v.created_by else None,
            "resident_list_category": _resident_category(v),
            "resident_name": v.created_by_user.name if v.created_by_user else None,
        })
    return results


def _resident_category(v) -> str:
    r = v.created_by_user
    return r.list_category.value if r and r.list_category else None


def _visitor_result(db: Session, v: "models.Visitor") -> dict:
    open_entry = (
        db.query(models.GateEntry)
        .filter(
            models.GateEntry.visitor_id == v.id,
            models.GateEntry.exit_time.is_(None),
        )
        .first()
    )
    return {
        "id": str(v.id),
        "name": v.name,
        "relationship_type": v.relationship_type,
        "visit_type": v.visit_type.value if v.visit_type else None,
        "status": v.effective_status().value,
        "valid_from": v.valid_from,
        "valid_until": v.valid_until,
        "phone": v.phone,
        "vehicle_plate": v.vehicle_plate,
        "lot_no": v.created_by_user.lot_no if v.created_by_user else None,
        "resident_id": str(v.created_by) if v.created_by else None,
        "on_site": open_entry is not None,
        "open_entry_id": str(open_entry.id) if open_entry else None,
        "resident_list_category": _resident_category(v),
        "resident_name": v.created_by_user.name if v.created_by_user else None,
    }


@router.get("/visitors/{visitor_id}", response_model=schemas.GateVisitorSearchResult)
def get_visitor(visitor_id: str, db: Session = Depends(get_db), _user=Depends(gate_user)):
    """Resolve one visitor by id — used when a guard scans a visitor's QR pass."""
    import uuid as _uuid
    try:
        _uuid.UUID(visitor_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=404, detail="Visitor pass not found")
    v = db.query(models.Visitor).filter(models.Visitor.id == visitor_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Visitor pass not found")
    return _visitor_result(db, v)


@router.post("/entries", response_model=schemas.GateEntry)
def log_entry(
    payload: schemas.GateEntryCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user=Depends(gate_user),
):
    """Log a visitor arriving at the gate. Validates the pass is usable and
    consumes one-time passes."""
    visitor = db.query(models.Visitor).filter(models.Visitor.id == payload.visitor_id).first()
    if not visitor:
        raise HTTPException(status_code=404, detail="Visitor not found")

    ok, reason = visitor.is_enterable()
    if not ok:
        raise HTTPException(status_code=403, detail=reason)

    # Optionally block visitors of a RED (delinquent) resident.
    if settings.gate_block_delinquent and _resident_category(visitor) == "RED":
        raise HTTPException(
            status_code=403,
            detail="Resident is on the delinquent (Red) list — entry not permitted. Please contact management.",
        )

    lot_no = visitor.created_by_user.lot_no if visitor.created_by_user else None
    entry = models.GateEntry(
        visitor_id=visitor.id,
        resident_id=visitor.created_by,
        lot_no=lot_no,
        logged_by=user.id,
        entry_time=int(time.time()),
        notes=payload.notes,
    )
    db.add(entry)

    # Consume one-time passes so they cannot be reused.
    if visitor.visit_type == VisitType.ONE_TIME:
        visitor.status = VisitorStatus.USED

    db.commit()
    db.refresh(entry)
    logger.info(f"Gate entry logged for visitor {visitor.name} (lot {lot_no}) by {user.email}")

    # Notify the resident their guest checked in (best-effort, in background).
    resident = visitor.created_by_user
    if resident and resident.user:
        background_tasks.add_task(
            notify_guest_movement,
            resident.user.email, resident.user.phone_number,
            visitor.name, lot_no, "checked in",
        )
    return entry.to_dict()


@router.put("/entries/{entry_id}/exit", response_model=schemas.GateEntry)
def log_exit(
    entry_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user=Depends(gate_user),
):
    """Stamp the exit time on an open gate entry."""
    entry = db.query(models.GateEntry).filter(models.GateEntry.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Gate entry not found")
    if entry.exit_time is not None:
        raise HTTPException(status_code=400, detail="Exit already logged for this entry")
    entry.exit_time = int(time.time())
    db.commit()
    db.refresh(entry)

    # Notify the resident their guest checked out (best-effort, in background).
    resident = entry.resident
    visitor_name = entry.visitor.name if entry.visitor else "Your visitor"
    if resident and resident.user:
        background_tasks.add_task(
            notify_guest_movement,
            resident.user.email, resident.user.phone_number,
            visitor_name, entry.lot_no, "checked out",
        )
    return entry.to_dict()


@router.get("/entries", response_model=list[schemas.GateEntry])
def list_entries(
    lot_no: Optional[str] = None,
    from_time: Optional[int] = Query(None, alias="from"),
    to_time: Optional[int] = Query(None, alias="to"),
    open: Optional[bool] = Query(None, description="Only visitors still on-site"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    _user=Depends(gate_user),
):
    """Audited gate log with optional filters (for the guard app & admin)."""
    query = db.query(models.GateEntry)
    if lot_no:
        query = query.filter(models.GateEntry.lot_no.ilike(f"%{lot_no.strip()}%"))
    if from_time is not None:
        query = query.filter(models.GateEntry.entry_time >= from_time)
    if to_time is not None:
        query = query.filter(models.GateEntry.entry_time <= to_time)
    if open:
        query = query.filter(models.GateEntry.exit_time.is_(None))

    entries = (
        query.order_by(desc(models.GateEntry.entry_time))
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [e.to_dict() for e in entries]

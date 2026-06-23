# app/routers/gate.py
"""Gate operations for security guards (and admins): manual visitor lookup,
logging arrivals/departures, and the audited gate log."""
import time
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from jose import JWTError, jwt
from sqlalchemy import or_, desc
from sqlalchemy.orm import Session

from .. import crud, models, schemas
from .. import audit
from .. import push
from ..database import SessionLocal
from ..enums import RoleEnum, VisitType, VisitorStatus
from ..utilities.db_util import get_db
from ..config.auth import require_roles, oauth2_scheme, _is_token_blacklisted
from ..config.config import settings
from ..notifications.service import notify_guest_movement
from ..realtime import event_stream
from ..services.zoho_sync import sync_resident, cache_is_fresh
from ..zoho_integration.zoho_client import ZohoClient
from ..logging_config import logger

router = APIRouter()
zoho_client = ZohoClient()

# Roles permitted to operate the gate, used by both the REST routes and the SSE
# stream's connection-time authorisation.
_GATE_ROLES = {RoleEnum.SECURITY.value, RoleEnum.ADMIN.value, RoleEnum.MANAGER.value}


def _ensure_resident_fresh(db: Session, resident) -> None:
    """Best-effort: refresh a resident's payment list/delinquency from Zoho if
    the cache is stale, so the gate's block decision reflects today's status.
    Never blocks the gate on a Zoho hiccup — falls back to the cached value."""
    if not resident or cache_is_fresh(resident, settings.zoho_cache_ttl):
        return
    try:
        if sync_resident(db, resident, zoho_client, with_invoices=False):
            db.commit()
    except Exception as e:  # Zoho down/slow — keep using the cached category
        db.rollback()
        logger.warning(f"Gate: could not refresh resident {resident.id} from Zoho: {e}")

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
    base = db.query(models.Visitor).join(
        models.Resident, models.Visitor.created_by == models.Resident.id
    )

    ql = q.strip().lower() if q and q.strip() else None
    lotl = lot_no.strip().lower() if lot_no and lot_no.strip() else None

    # name / phone / vehicle_plate / lot_no are encrypted at rest (AES-SIV), so a
    # SQL ILIKE matches ciphertext and never the plaintext. Substring search must
    # therefore happen in Python after the ORM transparently decrypts the rows.
    if not ql and not lotl:
        candidates = base.limit(limit).all()
    else:
        candidates = base.all()

        def _matches(v):
            if ql:
                hay = ' '.join(
                    s for s in [v.name, v.phone, v.vehicle_plate] if s
                ).lower()
                if ql not in hay:
                    return False
            if lotl:
                lot = (v.created_by_user.lot_no if v.created_by_user else '') or ''
                if lotl not in lot.lower():
                    return False
            return True

        candidates = [v for v in candidates if _matches(v)]

    visitors = sorted(candidates, key=lambda v: (v.name or '').lower())[:limit]

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


@router.get("/residents")
def directory(db: Session = Depends(get_db), _user=Depends(gate_user)):
    """Guard resident directory: verify authorized residents at the gate. Returns
    name, lot, phone (from the linked user), standing list and a real count of
    authorized vehicles (the resident's registered visitors that have a plate)."""
    residents = db.query(models.Resident).all()
    out = []
    for r in residents:
        vehicles = sum(
            1 for v in (r.visitors or []) if (v.vehicle_plate or "").strip()
        )
        out.append({
            "id": str(r.id),
            "name": r.name or "Resident",
            "lot_no": r.lot_no,
            "phone": r.user.phone_number if r.user else None,
            "list_category": r.list_category.value if r.list_category else "WHITE",
            "authorized_vehicles": vehicles,
            "role": "OWNER",
        })
    out.sort(key=lambda x: (x["lot_no"] or ""))
    return out


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
    request: Request = None,
):
    """Log a visitor arriving at the gate. Validates the pass is usable and
    consumes one-time passes."""
    visitor = db.query(models.Visitor).filter(models.Visitor.id == payload.visitor_id).first()
    if not visitor:
        raise HTTPException(status_code=404, detail="Visitor not found")

    ok, reason = visitor.is_enterable()
    if not ok:
        raise HTTPException(status_code=403, detail=reason)

    # The payment list can change daily, so make sure the resident's status is
    # current before deciding whether to block (best-effort; cached on failure).
    if settings.gate_block_delinquent:
        _ensure_resident_fresh(db, visitor.created_by_user)

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
    audit.record("gate.entry", user=user, request=request,
                 detail=f"visitor={visitor.id} entry={entry.id} lot={lot_no}")

    # Notify the resident their guest checked in (best-effort, in background).
    resident = visitor.created_by_user
    if resident and resident.user:
        background_tasks.add_task(
            notify_guest_movement,
            resident.user.email, resident.user.phone_number,
            visitor.name, lot_no, "checked in",
        )
        # Push only the owning resident: "your guest arrived" (best-effort).
        try:
            push.send_to_tokens(
                push.tokens_for_user(db, resident.user.id),
                "Guest arrived",
                f"{visitor.name or 'Your guest'} checked in at the gate.",
                data={"type": "gate.entry", "entry_id": str(entry.id),
                      "visitor_id": str(visitor.id)},
            )
        except Exception as e:
            logger.warning(f"FCM gate.entry push failed: {e}")
    return entry.to_dict()


@router.put("/entries/{entry_id}/exit", response_model=schemas.GateEntry)
def log_exit(
    entry_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user=Depends(gate_user),
    request: Request = None,
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
    audit.record("gate.exit", user=user, request=request,
                 detail=f"entry={entry.id} visitor={entry.visitor_id}")

    # Notify the resident their guest checked out (best-effort, in background).
    resident = entry.resident
    visitor_name = entry.visitor.name if entry.visitor else "Your visitor"
    if resident and resident.user:
        background_tasks.add_task(
            notify_guest_movement,
            resident.user.email, resident.user.phone_number,
            visitor_name, entry.lot_no, "checked out",
        )
    # Push the owning resident + all guards: visitor checked out (best-effort).
    try:
        recipients = set(push.tokens_for_guards(db))
        if resident and resident.user:
            recipients.update(push.tokens_for_user(db, resident.user.id))
        push.send_to_tokens(
            recipients,
            "Visitor checked out",
            f"{visitor_name} checked out at the gate.",
            data={"type": "gate.exit", "entry_id": str(entry.id),
                  "visitor_id": str(entry.visitor_id)},
        )
    except Exception as e:
        logger.warning(f"FCM gate.exit push failed: {e}")
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


def _authorize_gate_token(token: str) -> None:
    """Validate a bearer token for SSE access at connection time.

    The streaming endpoint can't use the usual ``Depends(get_db)`` dependency:
    that session would stay checked out for the entire (long-lived) stream and
    exhaust the connection pool. So we authenticate against a short-lived
    session that is closed immediately, then stream with no DB session held.
    """
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if _is_token_blacklisted(token):
        raise cred_exc
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except JWTError:
        raise cred_exc
    email = payload.get("sub")
    if not email:
        raise cred_exc

    db = SessionLocal()
    try:
        user = crud.get_user_by_email(db, email=email)
        if user is None:
            raise cred_exc
        role_name = (user.role.name if user.role else "") or ""
    finally:
        db.close()

    if role_name.upper() not in _GATE_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this resource.",
        )


@router.get("/events", include_in_schema=False)
async def gate_events(request: Request, token: str = Depends(oauth2_scheme)):
    """Server-Sent Events stream of live gate updates (e.g. a resident
    registering a visitor). Guards, managers and admins only. The connection is
    authorised once, up front; events then flow until the client disconnects."""
    _authorize_gate_token(token)
    return StreamingResponse(
        event_stream(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            # Tell any reverse proxy (nginx/Render) not to buffer the stream.
            "X-Accel-Buffering": "no",
        },
    )

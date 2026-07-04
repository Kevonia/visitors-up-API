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
from ..realtime import event_stream, publish_event
from ..services.gate_control import trigger_gate
from ..services.zoho_sync import sync_resident, cache_is_fresh
from ..zoho_integration.zoho_client import ZohoClient
from ..logging_config import logger

router = APIRouter()
zoho_client = ZohoClient()

# Roles permitted to operate the gate, used by both the REST routes and the SSE
# stream's connection-time authorisation.
_GATE_ROLES = {RoleEnum.SECURITY.value, RoleEnum.ADMIN.value, RoleEnum.MANAGER.value}


def _ensure_resident_fresh(db: Session, resident) -> None:
    """Keep the gate's block decision based on the CACHED status; never block a
    check-in on a synchronous Zoho HTTP call (critical under load). When the
    cache is stale, refresh in the background; if the queue is unavailable, fall
    back to a best-effort inline refresh that still won't fail the gate."""
    if not resident or cache_is_fresh(resident, settings.zoho_cache_ttl):
        return
    from ..queue import enqueue
    from ..jobs import refresh_resident_zoho
    if enqueue(refresh_resident_zoho, str(resident.id)):
        return  # refreshed out-of-band; this check-in uses the cached category
    # Queue unavailable → old inline behaviour (best-effort, cached on failure).
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
    name, lot, phone (from the linked user), standing list (Green/Yellow/Red) and
    the number of the resident's visitors currently on-site (open gate entries).

    Also includes Zoho contacts who have not yet registered for the app, tagged
    ``registered: false`` so guards can still look anyone up."""
    from sqlalchemy import func
    residents = db.query(models.Resident).all()
    # One grouped query for currently-on-site visitor counts per resident.
    onsite_rows = (
        db.query(models.GateEntry.resident_id, func.count(models.GateEntry.id))
        .filter(models.GateEntry.exit_time.is_(None))
        .group_by(models.GateEntry.resident_id)
        .all()
    )
    onsite_by_resident = {str(rid): cnt for rid, cnt in onsite_rows if rid}
    out = []
    for r in residents:
        out.append({
            "id": str(r.id),
            "name": r.name or "Resident",
            "lot_no": r.lot_no,
            "phone": r.user.phone_number if r.user else None,
            "list_category": r.list_category.value if r.list_category else "WHITE",
            "visitors_on_site": onsite_by_resident.get(str(r.id), 0),
            # Kept for backward-compat with already-shipped app builds; the new
            # directory shows visitors_on_site instead.
            "authorized_vehicles": sum(
                1 for v in (r.visitors or []) if (v.vehicle_plate or "").strip()
            ),
            "role": "OWNER",
            "registered": True,
        })
    # Append Zoho contacts with no app account yet (best-effort — never fail the
    # directory if Zoho is unreachable).
    try:
        from ..services.roster import (
            unregistered_contacts,
            name_from_contact,
            lot_from_contact,
            classify_contact,
            _contact_phone,
        )
        for c in unregistered_contacts(db):
            out.append({
                "id": None,
                "name": name_from_contact(c) or "Resident",
                "lot_no": lot_from_contact(c),
                "phone": _contact_phone(c) or None,
                "list_category": classify_contact(c).value,
                "visitors_on_site": 0,
                "authorized_vehicles": 0,
                "role": "OWNER",
                "registered": False,
            })
    except Exception as e:
        logger.warning(f"Gate directory: could not append unregistered Zoho contacts: {e}")
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

    # Consume one-time passes atomically BEFORE creating the entry: a conditional
    # UPDATE (status ACTIVE → USED) row-locks the visitor, so two concurrent
    # scans of the same pass can't both check in — the loser matches 0 rows.
    if visitor.visit_type == VisitType.ONE_TIME:
        claimed = (db.query(models.Visitor)
                   .filter(models.Visitor.id == visitor.id,
                           models.Visitor.status == VisitorStatus.ACTIVE)
                   .update({"status": VisitorStatus.USED}, synchronize_session=False))
        if not claimed:
            db.rollback()
            raise HTTPException(status_code=403, detail="This pass has already been used.")

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


# ── Gate opening (security app) ──────────────────────────────────────────────
# Debounce window: ignore a second open of the same gate within N seconds so a
# double-tap (or a retried request) doesn't pulse the relay twice.
_OPEN_DEBOUNCE_SECONDS = 4


@router.get("/gates", response_model=list[schemas.GateSummary])
def list_gates_for_guard(db: Session = Depends(get_db), _user=Depends(gate_user)):
    """Enabled gates the guard can open, for the app's gate picker."""
    rows = (db.query(models.Gate)
            .filter(models.Gate.enabled.is_(True))
            .order_by(models.Gate.name).all())
    return [
        {"id": str(g.id), "name": g.name, "location": g.location,
         "driver": g.driver.value if g.driver else "MANUAL"}
        for g in rows
    ]


@router.post("/{gate_id}/open", response_model=schemas.GateOpenResult)
def open_gate(
    gate_id: str,
    payload: schemas.GateOpenRequest,
    db: Session = Depends(get_db),
    user=Depends(gate_user),
    request: Request = None,
):
    """A guard opens a gate. Triggers the relay, records an audited open event,
    and broadcasts it live to the admin/gate console."""
    gate = db.query(models.Gate).filter(models.Gate.id == gate_id).first()
    if not gate:
        raise HTTPException(status_code=404, detail="Gate not found")
    if not gate.enabled:
        raise HTTPException(status_code=409, detail="Gate is disabled")

    # Debounce: a very recent open of this gate means the relay already fired.
    now = int(time.time())
    recent = (db.query(models.GateOpenEvent)
              .filter(models.GateOpenEvent.gate_id == gate.id,
                      models.GateOpenEvent.success.is_(True),
                      models.GateOpenEvent.created_at >= now - _OPEN_DEBOUNCE_SECONDS)
              .first())
    if recent:
        return {"success": True, "detail": "Gate already opening (debounced)",
                "event": recent.to_dict()}

    ok, detail = trigger_gate(gate.driver, gate.config_dict())
    event = models.GateOpenEvent(
        gate_id=gate.id,
        opened_by=user.id,
        visitor_id=payload.visitor_id,
        entry_id=payload.entry_id,
        reason=payload.reason,
        source="app",
        success=ok,
        detail=detail,
        created_at=now,
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    logger.info(f"Gate '{gate.name}' open by {user.email}: ok={ok} ({detail})")
    audit.record("gate.open", user=user, request=request,
                 status="success" if ok else "failure",
                 detail=f"gate={gate.id} reason={payload.reason} ok={ok}")
    try:
        publish_event("gate.opened", event.to_dict())
    except Exception as e:
        logger.warning(f"Gate open SSE publish failed: {e}")

    if not ok:
        # Surface the hardware failure to the guard so they open manually, but
        # keep the audited (failed) attempt above.
        raise HTTPException(status_code=502, detail=f"Gate did not open: {detail}")
    return {"success": ok, "detail": detail, "event": event.to_dict()}


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

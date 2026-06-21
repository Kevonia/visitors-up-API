"""Panic / SOS incidents.

Any authenticated user can raise one; guards/admins are alerted live (FCM push
+ SSE on the guards channel), then acknowledge and resolve it.
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

# Who can respond to (list/ack/resolve) incidents.
responder = require_roles(
    RoleEnum.SECURITY.value, RoleEnum.ADMIN.value, RoleEnum.MANAGER.value
)


@router.post("/incidents", response_model=schemas.IncidentOut)
def raise_incident(
    payload: schemas.IncidentCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Raise an SOS/panic alert. Open to any authenticated user."""
    user = crud.get_user_by_email(db, email=current_user.email)
    role = user.role.name if user and user.role else None
    resident = user.resident if user else None
    reporter_name = (resident.name if resident and resident.name
                     else (user.email if user else None))
    lot_no = payload.lot_no or (resident.lot_no if resident else None)

    incident = models.Incident(
        reported_by=user.id if user else None,
        reporter_role=role,
        reporter_name=reporter_name,
        lot_no=lot_no,
        kind=(payload.kind or "panic"),
        status="OPEN",
        note=payload.note,
        latitude=payload.latitude,
        longitude=payload.longitude,
        created_at=int(time.time()),
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    # Alert guards/admins live (best-effort, never fail the request).
    where = f"Lot {lot_no}" if lot_no else "the community"
    title = "SOS / Panic alert"
    body = f"{reporter_name or 'Someone'} raised a {incident.kind} alert at {where}."
    try:
        publish_event("incident.created", incident.to_dict(), guards=True)
    except Exception as e:
        logger.warning(f"SSE incident publish failed: {e}")
    try:
        push.send_to_tokens(
            push.tokens_for_guards(db), title, body,
            data={"type": "incident.created", "id": str(incident.id)},
        )
    except Exception as e:
        logger.warning(f"FCM incident push failed: {e}")
    return incident.to_dict()


@router.get("/incidents", response_model=list[schemas.IncidentOut])
def list_incidents(
    status: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    _user=Depends(responder),
):
    """Incidents, newest first; optional status filter (OPEN/ACKNOWLEDGED/RESOLVED)."""
    q = db.query(models.Incident)
    if status:
        q = q.filter(models.Incident.status == status.upper())
    rows = q.order_by(desc(models.Incident.created_at)).limit(limit).all()
    return [r.to_dict() for r in rows]


def _get_or_404(db: Session, incident_id: str) -> "models.Incident":
    inc = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@router.post("/incidents/{incident_id}/ack", response_model=schemas.IncidentOut)
def acknowledge_incident(
    incident_id: str, db: Session = Depends(get_db), user=Depends(responder),
):
    inc = _get_or_404(db, incident_id)
    if inc.status == "OPEN":
        inc.status = "ACKNOWLEDGED"
        inc.acknowledged_by = user.id
        inc.acknowledged_at = int(time.time())
        db.commit()
        db.refresh(inc)
        try:
            publish_event("incident.updated", inc.to_dict(), guards=True)
        except Exception:
            pass
    return inc.to_dict()


@router.post("/incidents/{incident_id}/resolve", response_model=schemas.IncidentOut)
def resolve_incident(
    incident_id: str, db: Session = Depends(get_db), user=Depends(responder),
):
    inc = _get_or_404(db, incident_id)
    if inc.status != "RESOLVED":
        inc.status = "RESOLVED"
        inc.resolved_by = user.id
        inc.resolved_at = int(time.time())
        db.commit()
        db.refresh(inc)
        try:
            publish_event("incident.updated", inc.to_dict(), guards=True)
        except Exception:
            pass
    return inc.to_dict()

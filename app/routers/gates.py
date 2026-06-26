"""Admin management of physical gates (the security-app gate-opening feature).

ADMIN/MANAGER configure gates here (name, location, driver + relay config) and
can fire a test pulse. The guard-facing "open" + "list gates" endpoints live in
``gate.py`` (the gate operations router). Mounted under /api/v1/admin.
"""
import json
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import desc
from sqlalchemy.orm import Session

from .. import models, schemas, audit
from ..enums import GateDriver, RoleEnum
from ..services.gate_control import trigger_gate
from ..utilities.db_util import get_db
from ..config.auth import require_roles
from ..logging_config import logger

router = APIRouter()

manager = require_roles(RoleEnum.ADMIN.value, RoleEnum.MANAGER.value)


def _parse_driver(value: str) -> GateDriver:
    try:
        return GateDriver(value.upper())
    except (ValueError, AttributeError):
        raise HTTPException(status_code=422, detail=f"Unknown gate driver '{value}'")


@router.get("/gates", response_model=list[schemas.GateOut])
def list_gates(db: Session = Depends(get_db), _user=Depends(manager)):
    rows = db.query(models.Gate).order_by(models.Gate.created_at).all()
    return [g.to_dict() for g in rows]


@router.post("/gates", response_model=schemas.GateOut)
def create_gate(
    payload: schemas.GateCreate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(manager),
):
    driver = _parse_driver(payload.driver)
    now = int(time.time())
    gate = models.Gate(
        name=payload.name,
        location=payload.location,
        driver=driver,
        config=json.dumps(payload.config or {}),
        enabled=payload.enabled,
        created_at=now,
        updated_at=now,
    )
    db.add(gate)
    db.commit()
    db.refresh(gate)
    audit.record("gate.config.create", user=user, request=request,
                 detail=f"gate={gate.id} name={gate.name} driver={driver.value}")
    return gate.to_dict()


@router.put("/gates/{gate_id}", response_model=schemas.GateOut)
def update_gate(
    gate_id: str,
    payload: schemas.GateUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(manager),
):
    gate = db.query(models.Gate).filter(models.Gate.id == gate_id).first()
    if not gate:
        raise HTTPException(status_code=404, detail="Gate not found")
    if payload.name is not None:
        gate.name = payload.name
    if payload.location is not None:
        gate.location = payload.location
    if payload.driver is not None:
        gate.driver = _parse_driver(payload.driver)
    if payload.config is not None:
        gate.config = json.dumps(payload.config or {})
    if payload.enabled is not None:
        gate.enabled = payload.enabled
    gate.updated_at = int(time.time())
    db.commit()
    db.refresh(gate)
    audit.record("gate.config.update", user=user, request=request, detail=f"gate={gate.id}")
    return gate.to_dict()


@router.delete("/gates/{gate_id}")
def delete_gate(
    gate_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(manager),
):
    gate = db.query(models.Gate).filter(models.Gate.id == gate_id).first()
    if not gate:
        raise HTTPException(status_code=404, detail="Gate not found")
    db.delete(gate)
    db.commit()
    audit.record("gate.config.delete", user=user, request=request, detail=f"gate={gate_id}")
    return {"deleted": True}


@router.post("/gates/{gate_id}/test", response_model=schemas.GateOpenResult)
def test_gate(
    gate_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(manager),
):
    """Fire a real pulse at the gate to verify the wiring, recorded as a test."""
    gate = db.query(models.Gate).filter(models.Gate.id == gate_id).first()
    if not gate:
        raise HTTPException(status_code=404, detail="Gate not found")

    ok, detail = trigger_gate(gate.driver, gate.config_dict())
    event = models.GateOpenEvent(
        gate_id=gate.id, opened_by=user.id, reason="test",
        source="test", success=ok, detail=detail, created_at=int(time.time()),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    audit.record("gate.test", user=user, request=request,
                 status="success" if ok else "failure",
                 detail=f"gate={gate.id} ok={ok} detail={detail}")
    logger.info(f"Gate test {gate.name} by {user.email}: ok={ok} ({detail})")
    return {"success": ok, "detail": detail, "event": event.to_dict()}


@router.get("/gate-open-events", response_model=list[schemas.GateOpenEventOut])
def list_open_events(
    limit: int = 100,
    db: Session = Depends(get_db),
    _user=Depends(manager),
):
    """Recent gate-open events (audit), newest first."""
    rows = (db.query(models.GateOpenEvent)
            .order_by(desc(models.GateOpenEvent.created_at))
            .limit(min(limit, 500)).all())
    return [e.to_dict() for e in rows]

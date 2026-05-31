# app/routers/guard_account.py
"""Admin-managed security guard accounts.

Guards are *not* residents: they have no Zoho contact and are not on the
allowlist, so they cannot self-register through /signup. An admin/manager
creates them here. A guard account is simply a User with the SECURITY role
and no associated Resident row.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import models, schemas
from ..enums import RoleEnum
from ..utilities.db_util import get_db
from ..utilities.authutil import get_password_hash
from ..config.auth import require_roles
from ..logging_config import logger

router = APIRouter()

_ADMIN = require_roles(RoleEnum.ADMIN.value, RoleEnum.MANAGER.value)


def _security_role(db: Session) -> models.Role:
    role = db.query(models.Role).filter(models.Role.name == RoleEnum.SECURITY.value).first()
    if not role:
        role = models.Role(name=RoleEnum.SECURITY.value, description="Security guard role")
        db.add(role)
        db.commit()
        db.refresh(role)
    return role


def _to_guard(user: models.User) -> dict:
    return {
        "id": str(user.id),
        "email": user.email,
        "phone_number": user.phone_number,
        "role": user.role.name if user.role else None,
        "created_at": user.created_at,
    }


@router.post("/guards", response_model=schemas.Guard, dependencies=[Depends(_ADMIN)])
def create_guard(guard: schemas.GuardCreate, db: Session = Depends(get_db)):
    """Create a SECURITY-role user (no resident, no Zoho/allowlist checks)."""
    existing = db.query(models.User).filter(
        (models.User.email == guard.email) | (models.User.phone_number == guard.phone_number)
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email or phone number already exists.",
        )

    role = _security_role(db)
    db_user = models.User(
        email=guard.email,
        phone_number=guard.phone_number,
        role_id=role.id,
        hashed_password=get_password_hash(guard.password),
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    logger.info(f"Created security guard account: {db_user.email}")
    return _to_guard(db_user)


@router.get("/guards", response_model=list[schemas.Guard], dependencies=[Depends(_ADMIN)])
def list_guards(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    role = db.query(models.Role).filter(models.Role.name == RoleEnum.SECURITY.value).first()
    if not role:
        return []
    guards = (
        db.query(models.User)
        .filter(models.User.role_id == role.id)
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [_to_guard(g) for g in guards]


@router.delete("/guards/{guard_id}", dependencies=[Depends(_ADMIN)])
def delete_guard(guard_id: str, db: Session = Depends(get_db)):
    role = db.query(models.Role).filter(models.Role.name == RoleEnum.SECURITY.value).first()
    db_user = db.query(models.User).filter(models.User.id == guard_id).first()
    if not db_user or (role and db_user.role_id != role.id):
        raise HTTPException(status_code=404, detail="Guard not found")
    db.delete(db_user)
    db.commit()
    return {"detail": "Guard account deleted"}

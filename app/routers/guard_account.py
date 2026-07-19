# app/routers/guard_account.py
"""Admin-managed staff accounts (security guards, managers, admins).

Staff are *not* residents: they have no Zoho contact and are not on the
allowlist, so they cannot self-register through /signup. An admin creates them
here. A staff account is simply a User with a staff role (SECURITY / MANAGER /
ADMIN) and no associated Resident row.

The routes are still mounted at /guards for backward compatibility with
already-shipped admin bundles; omitting ``role`` on create yields SECURITY,
which is exactly what those older builds send.
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

# Roles that can be minted from the admin panel.
STAFF_ROLES = (RoleEnum.ADMIN.value, RoleEnum.MANAGER.value, RoleEnum.SECURITY.value)

# Handing out a privileged account is itself a privilege. These routes are open
# to ADMIN *and* MANAGER, so without this split a MANAGER could create an ADMIN
# account (or promote via a new login) and escalate. Only an ADMIN may create or
# remove these roles; a MANAGER is limited to SECURITY accounts.
ELEVATED_ROLES = (RoleEnum.ADMIN.value, RoleEnum.MANAGER.value)


def _role_name(user) -> str:
    return ((user.role.name if user and user.role else "") or "").upper()


def _staff_role(db: Session, name: str) -> models.Role:
    """Get-or-create the Role row for a staff role name."""
    role = db.query(models.Role).filter(models.Role.name == name).first()
    if not role:
        role = models.Role(name=name, description=f"{name.capitalize()} role")
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


@router.post("/guards", response_model=schemas.Guard)
def create_guard(
    guard: schemas.GuardCreate,
    db: Session = Depends(get_db),
    current=Depends(_ADMIN),
):
    """Create a staff user (no resident, no Zoho/allowlist checks).

    ``role`` defaults to SECURITY so older admin builds keep working unchanged.
    """
    role_name = (guard.role or RoleEnum.SECURITY.value).upper()
    if role_name not in STAFF_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Role must be one of: {', '.join(STAFF_ROLES)}.",
        )
    if role_name in ELEVATED_ROLES and _role_name(current) != RoleEnum.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only an ADMIN can create ADMIN or MANAGER accounts.",
        )

    existing = db.query(models.User).filter(
        (models.User.email == guard.email) | (models.User.phone_number == guard.phone_number)
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email or phone number already exists.",
        )

    role = _staff_role(db, role_name)
    db_user = models.User(
        email=guard.email,
        phone_number=guard.phone_number,
        role_id=role.id,
        hashed_password=get_password_hash(guard.password),
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    logger.info(
        f"Created {role_name} staff account {db_user.email} "
        f"(by {getattr(current, 'email', '?')})"
    )
    return _to_guard(db_user)


@router.get("/guards", response_model=list[schemas.Guard], dependencies=[Depends(_ADMIN)])
def list_guards(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Every staff account (SECURITY, MANAGER and ADMIN), newest last."""
    role_ids = [
        r.id for r in db.query(models.Role).filter(models.Role.name.in_(STAFF_ROLES)).all()
    ]
    if not role_ids:
        return []
    staff = (
        db.query(models.User)
        .filter(models.User.role_id.in_(role_ids))
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [_to_guard(s) for s in staff]


@router.delete("/guards/{guard_id}")
def delete_guard(guard_id: str, db: Session = Depends(get_db), current=Depends(_ADMIN)):
    db_user = db.query(models.User).filter(models.User.id == guard_id).first()
    target_role = _role_name(db_user)
    if not db_user or target_role not in STAFF_ROLES:
        raise HTTPException(status_code=404, detail="Staff account not found")

    # Removing yourself would immediately end your own session.
    if str(db_user.id) == str(current.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot remove your own account.",
        )
    if target_role in ELEVATED_ROLES and _role_name(current) != RoleEnum.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only an ADMIN can remove ADMIN or MANAGER accounts.",
        )
    # Deleting the final ADMIN would lock everyone out of the admin panel with
    # no way back in, so refuse it.
    if target_role == RoleEnum.ADMIN.value:
        admin_role = db.query(models.Role).filter(
            models.Role.name == RoleEnum.ADMIN.value
        ).first()
        remaining = (
            db.query(models.User).filter(models.User.role_id == admin_role.id).count()
            if admin_role else 0
        )
        if remaining <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove the last ADMIN account.",
            )

    db.delete(db_user)
    db.commit()
    logger.info(
        f"Removed {target_role} staff account {db_user.email} "
        f"(by {getattr(current, 'email', '?')})"
    )
    return {"detail": "Staff account deleted"}

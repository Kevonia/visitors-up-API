"""Production bootstrap seeder: ensure the ADMIN and SECURITY accounts exist.

Designed to run on every deploy (e.g. from the container start command, right
after `alembic upgrade head`). It is idempotent — existing accounts are left
untouched — and credentials come from environment variables so production sets
strong secrets instead of the dev defaults:

    ADMIN_EMAIL / ADMIN_PASSWORD / ADMIN_PHONE
    SECURITY_EMAIL / SECURITY_PASSWORD / SECURITY_PHONE

PII (email/phone) is encrypted at rest automatically via the ORM. Passwords are
never logged.

Usage:
    python scripts/seed_prod.py
"""
import os
import sys

# Make `app` importable whether run as `python scripts/seed_prod.py` or `-m`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import SessionLocal  # noqa: E402
from app import models  # noqa: E402
from app.enums import RoleEnum  # noqa: E402
from app.config.config import settings  # noqa: E402
from app.utilities.authutil import get_password_hash  # noqa: E402


def _ensure_role(db, name: str) -> models.Role:
    role = db.query(models.Role).filter(models.Role.name == name).first()
    if not role:
        role = models.Role(name=name, description=f"{name} role")
        db.add(role)
        db.commit()
        db.refresh(role)
    return role


def _ensure_user(db, *, email: str, phone: str, password: str, role_name: str) -> None:
    existing = db.query(models.User).filter(
        (models.User.email == email) | (models.User.phone_number == phone)
    ).first()
    if existing:
        current = existing.role.name if existing.role else None
        print(f"SKIP {role_name}: {email} already exists (role={current}).")
        return
    role = _ensure_role(db, role_name)
    db.add(models.User(
        email=email,
        phone_number=phone,
        role_id=role.id,
        hashed_password=get_password_hash(password),
    ))
    db.commit()
    print(f"CREATED {role_name}: {email}")


def run() -> None:
    db = SessionLocal()
    try:
        _ensure_user(
            db,
            email=settings.admin_email,
            phone=settings.admin_phone,
            password=settings.admin_password,
            role_name=RoleEnum.ADMIN.value,
        )
        _ensure_user(
            db,
            email=settings.security_email,
            phone=settings.security_phone,
            password=settings.security_password,
            role_name=RoleEnum.SECURITY.value,
        )
        print("Bootstrap seeding complete.")
    finally:
        db.close()


if __name__ == "__main__":
    run()

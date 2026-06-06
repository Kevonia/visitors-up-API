"""Seed a SECURITY-role user (guard) for testing the security app.

A guard is a User with the SECURITY role and no Resident / Zoho / allowlist
requirement (mirrors POST /api/v1/guards). Idempotent: skips if the email or
phone already exists.

Usage (inside the web container):
    python scripts/seed_security.py [email] [password] [phone]

Defaults: security@twickenham.com / security123 / 18760000777
"""
import sys

from app.database import SessionLocal
from app import models
from app.enums import RoleEnum
from app.utilities.authutil import get_password_hash


def _security_role(db):
    role = db.query(models.Role).filter(
        models.Role.name == RoleEnum.SECURITY.value).first()
    if not role:
        role = models.Role(
            name=RoleEnum.SECURITY.value, description="Security guard role")
        db.add(role)
        db.commit()
        db.refresh(role)
    return role


def seed_security(email: str, password: str, phone: str) -> None:
    db = SessionLocal()
    try:
        existing = db.query(models.User).filter(
            (models.User.email == email) | (models.User.phone_number == phone)
        ).first()
        if existing:
            print(f"SKIP: user already exists -> {existing.email} "
                  f"(role={existing.role.name if existing.role else None})")
            return
        role = _security_role(db)
        user = models.User(
            email=email,
            phone_number=phone,
            role_id=role.id,
            hashed_password=get_password_hash(password),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        print(f"ADDED security user -> email={email} password={password} "
              f"phone={phone} id={user.id}")
    finally:
        db.close()


if __name__ == "__main__":
    email = sys.argv[1] if len(sys.argv) > 1 else "security@twickenham.com"
    password = sys.argv[2] if len(sys.argv) > 2 else "security123"
    phone = sys.argv[3] if len(sys.argv) > 3 else "18760000777"
    seed_security(email, password, phone)

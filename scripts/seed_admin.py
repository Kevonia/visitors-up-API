"""Seed an ADMIN (or other role) user for the admin web app.

ADMIN unlocks every admin screen (users, residents, roles, permissions,
announcements, allowlist, visitors, guards). Idempotent: skips if the email or
phone already exists.

Usage (inside the web container):
    python scripts/seed_admin.py [email] [password] [phone] [role]

Defaults: admin@twickenham.com / admin123 / 18760000111 / ADMIN
"""
import sys

from app.database import SessionLocal
from app import models
from app.enums import RoleEnum
from app.utilities.authutil import get_password_hash


def _role(db, name):
    role = db.query(models.Role).filter(models.Role.name == name).first()
    if not role:
        role = models.Role(name=name, description=f"{name} role")
        db.add(role)
        db.commit()
        db.refresh(role)
    return role


def seed_admin(email: str, password: str, phone: str, role_name: str) -> None:
    db = SessionLocal()
    try:
        existing = db.query(models.User).filter(
            (models.User.email == email) | (models.User.phone_number == phone)
        ).first()
        if existing:
            print(f"SKIP: user already exists -> {existing.email} "
                  f"(role={existing.role.name if existing.role else None})")
            return
        role = _role(db, role_name)
        user = models.User(
            email=email, phone_number=phone, role_id=role.id,
            hashed_password=get_password_hash(password),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        print(f"ADDED {role_name} user -> email={email} password={password} "
              f"phone={phone} id={user.id}")
    finally:
        db.close()


if __name__ == "__main__":
    email = sys.argv[1] if len(sys.argv) > 1 else "admin@twickenham.com"
    password = sys.argv[2] if len(sys.argv) > 2 else "admin123"
    phone = sys.argv[3] if len(sys.argv) > 3 else "18760000111"
    role = sys.argv[4] if len(sys.argv) > 4 else RoleEnum.ADMIN.value
    seed_admin(email, password, phone, role)

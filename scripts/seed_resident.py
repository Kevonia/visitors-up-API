"""Seed a single RESIDENT account for local testing / e2e.

Creates a User (role USER) plus a Resident record in good standing (no
delinquency, WHITE list, zero balance) so the add-visitor flow is not blocked
by the dues check in routers/user_visitor.py.

Idempotent: re-running leaves an existing user untouched.

Usage (inside the web container):
    python scripts/seed_resident.py [email] [password] [phone] [lot_no]

Defaults seed:  britianny1991@gmail.com / Test1234! / 18765551991 / E-1991
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import SessionLocal  # noqa: E402
from app import models  # noqa: E402
from app.enums import RoleEnum, StatusEnum, DelinquencyEnum, ListCategory  # noqa: E402
from app.utilities.authutil import get_password_hash  # noqa: E402


def _ensure_role(db, name: str) -> models.Role:
    role = db.query(models.Role).filter(models.Role.name == name).first()
    if not role:
        role = models.Role(name=name, description=f"{name} role")
        db.add(role)
        db.commit()
        db.refresh(role)
    return role


def run(email: str, password: str, phone: str, lot_no: str) -> None:
    db = SessionLocal()
    try:
        existing = db.query(models.User).filter(
            (models.User.email == email) | (models.User.phone_number == phone)
        ).first()
        if existing:
            has_resident = existing.resident is not None
            print(f"SKIP: {email} already exists "
                  f"(role={existing.role.name if existing.role else None}, "
                  f"resident={has_resident}).")
            return

        role = _ensure_role(db, RoleEnum.USER.value)
        user = models.User(
            email=email,
            phone_number=phone,
            role_id=role.id,
            hashed_password=get_password_hash(password),
        )
        db.add(user)
        db.flush()  # assign user.id

        resident = models.Resident(
            name="Britianny Walker",
            lot_no=lot_no,
            status=StatusEnum.ACTIVE,
            delinquency_status=DelinquencyEnum.INACTIVE,
            list_category=ListCategory.WHITE,
            outstanding_balance=0,
            user_id=user.id,
        )
        db.add(resident)
        db.commit()
        print(f"CREATED resident {email} (lot {lot_no}). Login password: {password}")
    finally:
        db.close()


if __name__ == "__main__":
    run(
        email=sys.argv[1] if len(sys.argv) > 1 else "britianny1991@gmail.com",
        password=sys.argv[2] if len(sys.argv) > 2 else "Test1234!",
        phone=sys.argv[3] if len(sys.argv) > 3 else "18765551991",
        lot_no=sys.argv[4] if len(sys.argv) > 4 else "E-1991",
    )

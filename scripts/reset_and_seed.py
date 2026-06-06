"""Truncate the data tables and reseed a clean demo dataset.

Because PII columns are now EncryptedStr, every row created here via the ORM is
written encrypted at rest. Roles/permissions are left intact (not PII). After
this runs the DB holds a known, fully-encrypted demo set:

  Residents (USER):  devtest@example.com / test1234   (lot from demo address)
                     kevonia123@gmail.com / test1234
  Security (SECURITY): security@twickenham.com / security123
  + allowlist entries, demo visitors, announcements, and a populated gate log.

Usage (inside the web container):
    python scripts/reset_and_seed.py
"""
import time

from sqlalchemy import text

from app.database import engine, SessionLocal
from app import models
from app.enums import RoleEnum, VisitType, VisitorStatus
from app.utilities.authutil import get_password_hash
from app.seed_roles import seed_roles
from app.demo_data import demo_address


RESIDENTS = [
    ("devtest@example.com", "18760000001", "test1234"),
    ("kevonia123@gmail.com", "18764898237", "test1234"),
]
SECURITY = ("security@twickenham.com", "18760000777", "security123")

ANNOUNCEMENTS = [
    ("Welcome to the Twickenham Glades app",
     "Manage your visitors, view invoices, and stay up to date with community announcements — all in one place.",
     "info", 1),
    ("Pool maintenance this Friday",
     "The community pool will be closed Friday 8am–2pm for scheduled cleaning. Thank you for your patience.",
     "maintenance", 2),
    ("Resident social — Saturday 5pm",
     "Join your neighbours at the clubhouse this Saturday from 5pm for food, music and games. Families welcome!",
     "event", 4),
    ("Gate access code change",
     "The visitor gate code will change on the 1st. Please share the new code with your expected guests only.",
     "urgent", 6),
]

DEMO_VISITORS = [
    {"name": "Marcia Brown", "relationship_type": "family",
     "visit_type": VisitType.PERMANENT, "phone": "18761234567"},
    {"name": "QuickMart Delivery", "relationship_type": "delivery",
     "visit_type": VisitType.ONE_TIME, "vehicle_plate": "PA1234"},
    {"name": "Andre Service Co.", "relationship_type": "service",
     "visit_type": VisitType.ONE_TIME, "phone": "18767654321"},
]


def truncate() -> None:
    with engine.begin() as conn:
        conn.execute(text(
            'TRUNCATE gate_entries, visitors, residents, announcements, '
            '"allowList", users RESTART IDENTITY CASCADE'
        ))
    print("Truncated data tables (roles/permissions kept).")


def _role(db, name):
    return db.query(models.Role).filter(models.Role.name == name).first()


def create_users(db) -> None:
    user_role = _role(db, RoleEnum.USER.value)
    sec_role = _role(db, RoleEnum.SECURITY.value)

    for email, phone, pw in RESIDENTS:
        db.add(models.AllowList(email=email, phone_number=phone))
    db.commit()

    for email, phone, pw in RESIDENTS:
        user = models.User(
            email=email, phone_number=phone, role_id=user_role.id,
            hashed_password=get_password_hash(pw),
        )
        db.add(user)
        db.flush()
        lot = demo_address(email).get("attention", "DEV")
        db.add(models.Resident(
            lot_no=f"{lot}-{str(user.id)[:8]}",
            status="ACTIVE",
            delinquency_status="INACTIVE",
            user_id=user.id,
        ))
    db.commit()
    print(f"Created {len(RESIDENTS)} resident user(s) + allowlist entries.")

    s_email, s_phone, s_pw = SECURITY
    db.add(models.User(
        email=s_email, phone_number=s_phone, role_id=sec_role.id,
        hashed_password=get_password_hash(s_pw),
    ))
    db.commit()
    print(f"Created security user {s_email}.")


def seed_announcements(db) -> None:
    now = int(time.time())
    for title, body, category, age_days in ANNOUNCEMENTS:
        db.add(models.Announcement(
            title=title, body=body, category=category,
            published_at=now - age_days * 86400, expires_at=None,
        ))
    db.commit()
    print(f"Seeded {len(ANNOUNCEMENTS)} announcements.")


def seed_visitors(db, email) -> None:
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not user.resident:
        print(f"Visitors: skipped (no resident for {email}).")
        return
    for v in DEMO_VISITORS:
        db.add(models.Visitor(
            name=v["name"], relationship_type=v["relationship_type"],
            visit_type=v.get("visit_type", VisitType.ONE_TIME),
            status=VisitorStatus.ACTIVE,
            phone=v.get("phone"), vehicle_plate=v.get("vehicle_plate"),
            created_by=user.resident.id,
        ))
    db.commit()
    print(f"Seeded {len(DEMO_VISITORS)} visitors for {email}.")


def seed_gate_entries(db) -> None:
    guard = (
        db.query(models.User)
        .join(models.Role, models.User.role_id == models.Role.id)
        .filter(models.Role.name == RoleEnum.SECURITY.value)
        .first()
    )
    visitors = db.query(models.Visitor).limit(3).all()
    if not guard or not visitors:
        print("Gate entries: skipped (need a guard + visitors).")
        return
    now = int(time.time())
    plans = [(2, None), (1, None), (26, 24)]
    for visitor, (in_h, out_h) in zip(visitors, plans):
        lot = visitor.created_by_user.lot_no if visitor.created_by_user else None
        db.add(models.GateEntry(
            visitor_id=visitor.id, resident_id=visitor.created_by, lot_no=lot,
            logged_by=guard.id, entry_time=now - in_h * 3600,
            exit_time=(now - out_h * 3600) if out_h is not None else None,
            notes="Demo entry",
        ))
    db.commit()
    print("Seeded gate entries (2 on-site, 1 completed).")


def run() -> None:
    truncate()
    seed_roles()  # idempotent; ensures USER/SECURITY/etc. exist
    db = SessionLocal()
    try:
        create_users(db)
        seed_announcements(db)
        seed_visitors(db, RESIDENTS[0][0])
        seed_gate_entries(db)
    finally:
        db.close()
    print("Done. Database reseeded with encrypted values.")


if __name__ == "__main__":
    run()

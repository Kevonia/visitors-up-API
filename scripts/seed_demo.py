"""Seed local demo data: announcements (always) and demo visitors for a resident.

Usage (inside the web container):
    python scripts/seed_demo.py [resident_email]

- Announcements are seeded idempotently (matched by title) so the Updates tab
  in the app is populated.
- If a resident_email is given and that user has a Resident record, a few demo
  visitors are seeded for them (idempotent by name) so the Visitors tab is
  populated too.
"""
import sys
import time

from app.database import SessionLocal
from app import models
from app.enums import VisitType, VisitorStatus, RoleEnum


ANNOUNCEMENTS = [
    {
        "title": "Welcome to the Twickenham Glades app",
        "body": "Manage your visitors, view invoices, and stay up to date with "
                "community announcements — all in one place.",
        "category": "info",
        "age_days": 1,
    },
    {
        "title": "Pool maintenance this Friday",
        "body": "The community pool will be closed Friday 8am–2pm for scheduled "
                "cleaning and chemical balancing. Thank you for your patience.",
        "category": "maintenance",
        "age_days": 2,
    },
    {
        "title": "Resident social — Saturday 5pm",
        "body": "Join your neighbours at the clubhouse this Saturday from 5pm for "
                "food, music and games. Families welcome!",
        "category": "event",
        "age_days": 4,
    },
    {
        "title": "Gate access code change",
        "body": "The visitor gate code will change on the 1st. Please share the new "
                "code with your expected guests only.",
        "category": "urgent",
        "age_days": 6,
    },
]


DEMO_VISITORS = [
    {"name": "Marcia Brown", "relationship_type": "family",
     "visit_type": VisitType.PERMANENT, "phone": "18761234567"},
    {"name": "QuickMart Delivery", "relationship_type": "delivery",
     "visit_type": VisitType.ONE_TIME, "vehicle_plate": "PA1234"},
    {"name": "Andre Service Co.", "relationship_type": "service",
     "visit_type": VisitType.ONE_TIME, "phone": "18767654321"},
]


def seed_announcements(db) -> None:
    now = int(time.time())
    added = 0
    for a in ANNOUNCEMENTS:
        exists = db.query(models.Announcement).filter(
            models.Announcement.title == a["title"]).first()
        if exists:
            continue
        db.add(models.Announcement(
            title=a["title"],
            body=a["body"],
            category=a["category"],
            published_at=now - a["age_days"] * 86400,
            expires_at=None,
        ))
        added += 1
    db.commit()
    print(f"Announcements: {added} added, {len(ANNOUNCEMENTS) - added} already present")


def seed_visitors(db, email: str) -> None:
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not user.resident:
        print(f"Visitors: skipped (no resident found for {email})")
        return
    resident_id = user.resident.id
    added = 0
    for v in DEMO_VISITORS:
        exists = db.query(models.Visitor).filter(
            models.Visitor.name == v["name"],
            models.Visitor.created_by == resident_id,
        ).first()
        if exists:
            continue
        db.add(models.Visitor(
            name=v["name"],
            relationship_type=v["relationship_type"],
            visit_type=v.get("visit_type", VisitType.ONE_TIME),
            status=VisitorStatus.ACTIVE,
            phone=v.get("phone"),
            vehicle_plate=v.get("vehicle_plate"),
            created_by=resident_id,
        ))
        added += 1
    db.commit()
    print(f"Visitors for {email}: {added} added")


def seed_gate_entries(db) -> None:
    """Populate the gate log so the security app has data to show.

    Logs a couple of visitors as currently on-site (open entries) and one as a
    completed visit, attributed to a SECURITY guard. Idempotent: skips entirely
    if any gate entries already exist.
    """
    if db.query(models.GateEntry).count() > 0:
        print("Gate entries: skipped (log already has entries)")
        return

    guard = (
        db.query(models.User)
        .join(models.Role, models.User.role_id == models.Role.id)
        .filter(models.Role.name == RoleEnum.SECURITY.value)
        .first()
    )
    if not guard:
        print("Gate entries: skipped (no SECURITY user — run seed_security.py first)")
        return

    visitors = (
        db.query(models.Visitor)
        .filter(models.Visitor.created_by.isnot(None))
        .limit(3)
        .all()
    )
    if not visitors:
        print("Gate entries: skipped (no visitors to log)")
        return

    now = int(time.time())
    plans = [
        # (hours_ago_entry, hours_ago_exit or None)
        (2, None),       # on-site now
        (1, None),       # on-site now
        (26, 24),        # completed visit yesterday
    ]
    added = 0
    for visitor, (in_h, out_h) in zip(visitors, plans):
        lot_no = visitor.created_by_user.lot_no if visitor.created_by_user else None
        db.add(models.GateEntry(
            visitor_id=visitor.id,
            resident_id=visitor.created_by,
            lot_no=lot_no,
            logged_by=guard.id,
            entry_time=now - in_h * 3600,
            exit_time=(now - out_h * 3600) if out_h is not None else None,
            notes="Demo entry",
        ))
        added += 1
    db.commit()
    print(f"Gate entries: {added} added (logged by {guard.email})")


if __name__ == "__main__":
    email = sys.argv[1] if len(sys.argv) > 1 else None
    db = SessionLocal()
    try:
        seed_announcements(db)
        if email:
            seed_visitors(db, email)
        seed_gate_entries(db)
    finally:
        db.close()

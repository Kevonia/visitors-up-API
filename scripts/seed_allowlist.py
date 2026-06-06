"""Idempotently add an (email, phone_number) pair to the AllowList table.

Usage (inside the api environment / web container):
    python scripts/seed_allowlist.py <email> <phone_number>

Registration (`POST /api/v1/signup/`) requires the phone number to exist in the
AllowList, so this is how you authorize a resident to self-register.
"""
import sys

from app.database import SessionLocal
from app import models


def add_to_allowlist(email: str, phone_number: str) -> None:
    db = SessionLocal()
    try:
        existing = (
            db.query(models.AllowList)
            .filter(
                (models.AllowList.email == email)
                | (models.AllowList.phone_number == phone_number)
            )
            .first()
        )
        if existing:
            print(
                f"SKIP: already present -> email={existing.email} "
                f"phone={existing.phone_number} id={existing.id}"
            )
            return

        entry = models.AllowList(email=email, phone_number=phone_number)
        db.add(entry)
        db.commit()
        db.refresh(entry)
        print(f"ADDED: email={entry.email} phone={entry.phone_number} id={entry.id}")
    finally:
        db.close()


if __name__ == "__main__":
    email = sys.argv[1] if len(sys.argv) > 1 else "kevonia123@gmail.com"
    phone = sys.argv[2] if len(sys.argv) > 2 else "18764898237"
    add_to_allowlist(email, phone)

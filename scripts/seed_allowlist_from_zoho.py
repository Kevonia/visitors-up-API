"""Truncate all data and seed the allowlist from the Zoho contacts.

Wipes the resident-facing data tables (keeps roles/permissions), then inserts an
AllowList row for every Zoho contact that has an email, so those residents can
self-register. Contacts are keyed by email; phone is stored when present (empty
-> NULL, since the phone column is unique and Postgres allows multiple NULLs).
Re-run scripts/seed_prod.py afterwards (or restart the web container) to recreate
the ADMIN/SECURITY accounts.

Contacts are read from api/zoho_contacts.json if present, else fetched live.

Usage (inside the web container):
    python scripts/seed_allowlist_from_zoho.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text  # noqa: E402

from app.database import engine, SessionLocal  # noqa: E402
from app import models  # noqa: E402

_SNAPSHOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "zoho_contacts.json")


def load_contacts() -> list:
    if os.path.exists(_SNAPSHOT):
        data = json.load(open(_SNAPSHOT, encoding="utf-8"))
        contacts = data.get("contacts", data) if isinstance(data, dict) else data
        print(f"Loaded {len(contacts)} contacts from zoho_contacts.json")
        return contacts
    # Fallback: fetch live (paged).
    from app.zoho_integration.zoho_client import ZohoClient
    zc = ZohoClient()
    out, page = [], 1
    while True:
        d = zc.make_request("contacts", params={"page": page, "per_page": 200})
        out.extend(d.get("contacts", []))
        if not d.get("page_context", {}).get("has_more_page"):
            break
        page += 1
    print(f"Fetched {len(out)} contacts live from Zoho")
    return out


def truncate() -> None:
    with engine.begin() as conn:
        conn.execute(text(
            'TRUNCATE cached_invoices, gate_entries, visitors, residents, '
            'announcements, "allowList", users RESTART IDENTITY CASCADE'
        ))
    print("Truncated all data tables (roles/permissions kept).")


def seed_allowlist(contacts: list) -> None:
    db = SessionLocal()
    seen_emails, seen_phones = set(), set()
    added = 0
    try:
        for c in contacts:
            email = (c.get("email") or "").strip().lower()
            if not email or email in seen_emails:
                continue
            phone = (c.get("phone") or c.get("mobile") or "").strip() or None
            if phone and phone in seen_phones:
                phone = None  # keep the unique phone index happy
            db.add(models.AllowList(email=email, phone_number=phone))
            seen_emails.add(email)
            if phone:
                seen_phones.add(phone)
            added += 1
        db.commit()
        print(f"Seeded {added} allowlist entries from contacts.")
    finally:
        db.close()


def run() -> None:
    contacts = load_contacts()
    truncate()
    seed_allowlist(contacts)
    print("Done. Run scripts/seed_prod.py (or restart web) to recreate admin/security.")


if __name__ == "__main__":
    run()

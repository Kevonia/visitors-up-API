"""Community roster: every Zoho contact, flagged registered / not-registered.

"Registered" = the Zoho contact matches a Resident's linked User (by email or
phone), i.e. that person has signed up in the app. Unregistered contacts are
Zoho contacts with no app account yet.

The expensive part (paging every Zoho contact) is cached in Redis by
``ZohoClient.get_all_contacts``; the registered/not-registered split is computed
fresh from the DB on each call so newly-signed-up residents show immediately.
"""
from sqlalchemy.orm import Session

from app import models
from app.services.lists import classify_contact, get_outstanding_balance
from app.services.zoho_sync import name_from_contact, lot_from_contact
from app.zoho_integration.zoho_client import ZohoClient

zoho_client = ZohoClient()


def _norm_email(s) -> str:
    return (s or "").strip().lower()


def _norm_phone(s) -> str:
    return (s or "").replace("-", "").strip()


def _contact_email(c: dict) -> str:
    return _norm_email(c.get("email"))


def _contact_phone(c: dict) -> str:
    return _norm_phone(c.get("phone") or c.get("mobile"))


def resident_match_maps(db: Session):
    """Return (by_email, by_phone) mapping normalized email/phone -> Resident for
    every registered resident (one linked to a User)."""
    residents = db.query(models.Resident).all()
    by_email, by_phone = {}, {}
    for r in residents:
        u = r.user
        if not u:
            continue
        if u.email:
            by_email[_norm_email(u.email)] = r
        if u.phone_number:
            by_phone[_norm_phone(u.phone_number)] = r
    return by_email, by_phone


def match_resident(c: dict, by_email: dict, by_phone: dict):
    """The Resident this Zoho contact belongs to, or None if not registered."""
    r = by_email.get(_contact_email(c))
    if r is None:
        phone = _contact_phone(c)
        if phone:
            r = by_phone.get(phone)
    return r


def _registered_row(r, c) -> dict:
    return {
        "id": str(r.id),
        "user_id": str(r.user_id) if r.user_id else None,
        "name": r.name or (name_from_contact(c) if c else None),
        "lot_no": r.lot_no or (lot_from_contact(c) if c else None),
        "email": (_norm_email(r.user.email) if r.user and r.user.email else None)
        or (_contact_email(c) if c else None)
        or None,
        "phone": (r.user.phone_number if r.user else None)
        or (_contact_phone(c) if c else None)
        or None,
        "status": r.status.value if r.status else None,
        "delinquency_status": r.delinquency_status.value if r.delinquency_status else None,
        "list_category": r.list_category.value if r.list_category else "WHITE",
        "outstanding_balance": r.outstanding_balance or 0,
        "created_at": r.created_at,
        "updated_at": r.updated_at,
        "registered": True,
    }


def _unregistered_row(c: dict) -> dict:
    return {
        "id": None,
        "user_id": None,
        "name": name_from_contact(c),
        "lot_no": lot_from_contact(c),
        "email": _contact_email(c) or None,
        "phone": _contact_phone(c) or None,
        "status": None,
        "delinquency_status": None,
        "list_category": classify_contact(c).value,
        "outstanding_balance": get_outstanding_balance(c),
        "registered": False,
    }


def build_roster(db: Session) -> list[dict]:
    """Every Zoho contact + a ``registered`` flag. Also includes any registered
    resident whose Zoho contact wasn't in the pull, so the roster is always a
    superset of the current residents list."""
    contacts = zoho_client.get_all_contacts()
    by_email, by_phone = resident_match_maps(db)
    matched_ids = set()
    rows = []
    for c in contacts:
        r = match_resident(c, by_email, by_phone)
        if r is not None:
            matched_ids.add(str(r.id))
            rows.append(_registered_row(r, c))
        else:
            rows.append(_unregistered_row(c))
    # Registered residents not present in the Zoho pull (email mismatch, etc.).
    residents_by_id = {str(r.id): r for r in (*by_email.values(), *by_phone.values())}
    for rid, r in residents_by_id.items():
        if rid not in matched_ids:
            rows.append(_registered_row(r, None))
    rows.sort(key=lambda x: (x["lot_no"] or "", (x["name"] or "").lower()))
    return rows


def unregistered_contacts(db: Session) -> list[dict]:
    """Zoho contacts with no linked app account — for the gate directory."""
    contacts = zoho_client.get_all_contacts()
    by_email, by_phone = resident_match_maps(db)
    return [c for c in contacts if match_resident(c, by_email, by_phone) is None]

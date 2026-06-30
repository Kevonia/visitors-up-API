"""Apply a Zoho contact (+ invoices) onto a Resident and cache them in the DB.

Shared by signup, the admin /zoho/sync, and the lazy refresh on /users/me, so
the list category and invoices are computed once and read from our DB after.
"""
import time

from sqlalchemy.orm import Session

from app import models
from app.enums import DelinquencyEnum
from app.services.lists import (
    classify_contact,
    get_on_payment_plan,
    get_outstanding_balance,
    is_delinquent,
)


def _cf(contact: dict, key: str):
    return (contact.get("custom_field_hash") or {}).get(key)


def lot_from_contact(contact: dict) -> str:
    """The real lot number lives in the cf_lot_number custom field (the address
    'attention' line is actually the resident's name)."""
    lot = _cf(contact, "cf_lot_number")
    return str(lot) if lot not in (None, "") else None


def name_from_contact(contact: dict) -> str:
    return contact.get("contact_name") or contact.get("customer_name")


def apply_contact(resident: models.Resident, contact: dict) -> None:
    """Set a resident's cached Zoho fields from a contact dict (no commit)."""
    category = classify_contact(contact)
    resident.list_category = category
    resident.name = name_from_contact(contact)
    lot = lot_from_contact(contact)
    if lot:
        resident.lot_no = lot
    resident.on_payment_plan = get_on_payment_plan(contact) or None
    resident.outstanding_balance = get_outstanding_balance(contact)
    resident.customer_status = contact.get("status")
    resident.zoho_contact_id = contact.get("contact_id")
    street = _cf(contact, "cf_street_name")
    if street:
        resident.street_name = street
    # Keep the legacy delinquency flag in sync (RED == delinquent).
    resident.delinquency_status = (
        DelinquencyEnum.ACTIVE if is_delinquent(category) else DelinquencyEnum.INACTIVE
    )
    resident.zoho_synced_at = int(time.time())


def cache_invoices(db: Session, resident: models.Resident, invoices: list) -> int:
    """Replace the resident's cached invoices with the given Zoho invoices."""
    db.query(models.CachedInvoice).filter(
        models.CachedInvoice.resident_id == resident.id
    ).delete(synchronize_session=False)
    now = int(time.time())
    count = 0
    for inv in invoices or []:
        db.add(models.CachedInvoice(
            resident_id=resident.id,
            invoice_id=inv.get("invoice_id"),
            invoice_number=inv.get("invoice_number"),
            status=inv.get("status"),
            total=float(inv.get("total") or 0),
            balance=float(inv.get("balance") or 0),
            due_date=inv.get("due_date"),
            date=inv.get("date"),
            last_payment_date=inv.get("last_payment_date"),
            currency_code=inv.get("currency_code"),
            company_name=inv.get("company_name"),
            invoice_url=inv.get("invoice_url"),
            synced_at=now,
        ))
        count += 1
    return count


def sync_resident(db: Session, resident: models.Resident, zoho_client, with_invoices: bool = True) -> bool:
    """Fetch a resident's Zoho contact (+ invoices) and refresh the DB cache.

    Returns True if a contact was found and applied. Caller commits.
    """
    user = resident.user
    if not user or not user.email:
        return False
    contact = zoho_client.get_contact_by_email(user.email)
    if not contact:
        return False
    apply_contact(resident, contact)
    if with_invoices and contact.get("contact_id"):
        invoices = zoho_client.get_invoices_for_contact(contact["contact_id"])
        cache_invoices(db, resident, invoices)
    # The sync just overwrote invoices/standing from Zoho — re-apply any in-app
    # payments Zoho hasn't reflected yet so a paid resident never reverts.
    from .payment_service import reapply_unreconciled_payments
    reapply_unreconciled_payments(db, resident)
    return True


def cache_is_fresh(resident: models.Resident, ttl: int) -> bool:
    return bool(resident.zoho_synced_at and (int(time.time()) - resident.zoho_synced_at) < ttl)

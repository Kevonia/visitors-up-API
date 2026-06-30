"""Apply a QuickBooks customer (+ invoices) onto a Resident and cache them.

The QBO counterpart to services/zoho_sync.py. Reuses the same Resident cached
fields + CachedInvoice rows + White/Yellow/Red logic, so the rest of the app
(gate, dashboard, /users/me) is unchanged regardless of accounting provider.
QBO has no "on payment plan" concept by default, so residents are White/Red by
balance unless a custom field is later mapped.
"""
import time

from sqlalchemy.orm import Session

from app import models
from app.config.config import settings
from app.enums import DelinquencyEnum
from app.services.lists import classify_from_balance, is_delinquent


def _email_of(customer: dict) -> str:
    return ((customer.get("PrimaryEmailAddr") or {}).get("Address") or "").strip()


def _on_payment_plan(customer: dict) -> str:
    """Read the configured QBO custom field that flags a payment plan.
    Returns 'Y' / 'N' / '' (field absent or feature disabled)."""
    target = (settings.qbo_payment_plan_field or "").strip().lower()
    if not target:
        return ""
    for cf in customer.get("CustomField") or []:
        if str(cf.get("Name") or "").strip().lower() == target:
            val = str(cf.get("StringValue") or "").strip().upper()
            return "Y" if val in ("Y", "YES", "TRUE", "1") else "N"
    return ""


def apply_customer(resident: models.Resident, customer: dict) -> None:
    """Set a resident's cached fields from a QBO Customer dict (no commit)."""
    outstanding = float(customer.get("Balance") or 0)
    resident.name = customer.get("DisplayName") or customer.get("CompanyName") or resident.name
    resident.outstanding_balance = outstanding
    # Yellow comes from a configurable QBO custom field (blank disables it).
    plan = _on_payment_plan(customer)
    resident.on_payment_plan = plan or None
    category = classify_from_balance(outstanding, plan)
    resident.list_category = category
    resident.customer_status = "Active" if customer.get("Active", True) else "Inactive"
    # Reuse the existing accounting-customer-id column.
    resident.zoho_contact_id = str(customer.get("Id")) if customer.get("Id") else None
    resident.delinquency_status = (
        DelinquencyEnum.ACTIVE if is_delinquent(category) else DelinquencyEnum.INACTIVE
    )
    resident.zoho_synced_at = int(time.time())


def _invoice_status(inv: dict) -> str:
    bal = float(inv.get("Balance") or 0)
    total = float(inv.get("TotalAmt") or 0)
    if bal <= 0:
        return "paid"
    if 0 < bal < total:
        return "partially_paid"
    return "overdue"


def cache_invoices(db: Session, resident: models.Resident, invoices: list) -> int:
    """Replace the resident's cached invoices with the given QBO invoices."""
    db.query(models.CachedInvoice).filter(
        models.CachedInvoice.resident_id == resident.id
    ).delete(synchronize_session=False)
    now = int(time.time())
    count = 0
    for inv in invoices or []:
        db.add(models.CachedInvoice(
            resident_id=resident.id,
            invoice_id=str(inv.get("Id")) if inv.get("Id") else None,
            invoice_number=inv.get("DocNumber"),
            status=_invoice_status(inv),
            total=float(inv.get("TotalAmt") or 0),
            balance=float(inv.get("Balance") or 0),
            due_date=inv.get("DueDate"),
            date=inv.get("TxnDate"),
            last_payment_date=None,
            currency_code=(inv.get("CurrencyRef") or {}).get("value"),
            company_name=None,
            invoice_url=None,
            synced_at=now,
        ))
        count += 1
    return count


def sync_resident(db: Session, resident: models.Resident, qb_client, with_invoices: bool = True) -> bool:
    """Fetch a resident's QBO customer (+ invoices) and refresh the DB cache.
    Returns True if a customer was found and applied. Caller commits."""
    user = resident.user
    if not user or not user.email:
        return False
    customer = qb_client.get_customer_by_email(user.email)
    if not customer:
        return False
    apply_customer(resident, customer)
    if with_invoices and customer.get("Id"):
        invoices = qb_client.get_invoices_for_customer(customer["Id"])
        cache_invoices(db, resident, invoices)
    # Preserve in-app payments QBO hasn't reflected yet (see zoho_sync).
    from .payment_service import reapply_unreconciled_payments
    reapply_unreconciled_payments(db, resident)
    return True

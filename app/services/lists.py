"""Resident payment-list classification from a Zoho contact.

Single source of truth for Yellow / Red / White. Derived entirely from the
contact object (the "On Payment Plan" custom field + the contact-level
outstanding balance), so it never needs a per-invoice scan.
"""
from app.config.config import settings
from app.enums import ListCategory

_ON_PAYMENT_PLAN_KEY = "cf_on_payment_plan"
_ON_PAYMENT_PLAN_LABEL = "On Payment Plan"


def get_on_payment_plan(contact: dict) -> str:
    """Return the normalised 'On Payment Plan' value ('Y' / 'N' / '')."""
    if not isinstance(contact, dict):
        return ""
    val = (contact.get("custom_field_hash") or {}).get(_ON_PAYMENT_PLAN_KEY)
    if val is None:
        for cf in contact.get("custom_fields") or []:
            if cf.get("label") == _ON_PAYMENT_PLAN_LABEL or cf.get("api_name") == _ON_PAYMENT_PLAN_KEY:
                val = cf.get("value")
                break
    return (val or "").strip().upper()


def get_outstanding_balance(contact: dict) -> float:
    try:
        return float((contact or {}).get("outstanding_receivable_amount") or 0)
    except (TypeError, ValueError):
        return 0.0


def classify_contact(contact: dict) -> ListCategory:
    """Yellow if on a payment plan; Red if delinquent (over threshold); else White."""
    if get_on_payment_plan(contact) == "Y":
        return ListCategory.YELLOW
    if get_outstanding_balance(contact) > settings.red_balance_threshold:
        return ListCategory.RED
    return ListCategory.WHITE


def is_delinquent(category: ListCategory) -> bool:
    return category == ListCategory.RED

"""Local/dev demo data shaped like the Zoho Invoice API responses.

Used when DEV_SKIP_ZOHO is enabled so that /users/me and /users/me/invoices
return realistic, populated data without a live Zoho connection. Every dict
here is built to satisfy the schemas in app/schemas.py (Contact, Address,
Invoice). Values are derived deterministically from the user's email so the
same user always sees the same data across requests.
"""
from datetime import datetime, timedelta
import hashlib


def _seed(email: str) -> int:
    """Stable integer seed from an email (no randomness, survives restarts)."""
    digest = hashlib.sha256((email or "demo").encode()).hexdigest()
    return int(digest[:8], 16)


def _empty_address() -> dict:
    return {
        "address_id": 0,
        "attention": "",
        "address": "",
        "street2": "",
        "city": "",
        "state": "",
        "zip": "",
        "country": "",
        "fax": "",
        "phone": "",
    }


def demo_address(email: str) -> dict:
    """A populated address; `attention` carries the lot number (as in Zoho)."""
    seed = _seed(email)
    lot = f"{chr(65 + seed % 6)}-{100 + seed % 80}"  # e.g. "C-137"
    return {
        "address_id": 1000 + seed % 9000,
        "attention": lot,
        "address": f"{1 + seed % 200} Glades Drive",
        "street2": "Twickenham Glades",
        "city": "Kingston",
        "state": "St. Andrew",
        "zip": "JMAKN05",
        "country": "Jamaica",
        "fax": "",
        "phone": "",
    }


def _invoice(
    *,
    email: str,
    idx: int,
    number: str,
    status: str,
    sub_status: str,
    total: float,
    balance: float,
    date: datetime,
    due_date: datetime,
    color_code: str,
) -> dict:
    """One invoice dict satisfying schemas.Invoice (all required fields set)."""
    addr = demo_address(email)
    fmt = "%Y-%m-%d"
    iso = "%Y-%m-%dT%H:%M:%S%z"
    due_days = (due_date - datetime.utcnow()).days
    return {
        "ach_payment_initiated": False,
        "invoice_id": f"demo-inv-{_seed(email)}-{idx}",
        "zcrm_potential_id": "",
        "customer_id": f"demo-{_seed(email)}",
        "zcrm_potential_name": "",
        "customer_name": email,
        "company_name": "Twickenham Glades HOA",
        "status": status,
        "invoice_number": number,
        "reference_number": "",
        "date": date.strftime(fmt),
        "due_date": due_date.strftime(fmt),
        "due_days": str(due_days),
        "email": email,
        "project_name": "",
        "billing_address": addr,
        "shipping_address": addr,
        "country": "Jamaica",
        "phone": "",
        "created_by": "Twickenham Glades HOA",
        "total": round(total, 2),
        "balance": round(balance, 2),
        "payment_expected_date": "",
        "custom_fields": [],
        "custom_field_hash": {},
        "salesperson_name": "",
        "shipping_charge": 0.0,
        "adjustment": 0.0,
        "created_time": date.strftime(iso) or date.strftime(fmt),
        "last_modified_time": date.strftime(fmt),
        "updated_time": date.strftime(fmt),
        "is_viewed_by_client": True,
        "has_attachment": False,
        "client_viewed_time": "",
        "is_emailed": True,
        "color_code": color_code,
        "current_sub_status_id": "",
        "current_sub_status": sub_status,
        "currency_id": "",
        "schedule_time": "",
        "currency_code": "JMD",
        "currency_symbol": "$",
        "template_type": "standard",
        "no_of_copies": 1,
        "show_no_of_copies": True,
        "invoice_url": "",
        "transaction_type": "invoice",
        "reminders_sent": 0,
        "last_reminder_sent_date": "",
        "last_payment_date": "",
        "template_id": "",
        "documents": "",
        "salesperson_id": "",
        "write_off_amount": 0.0,
        "exchange_rate": 1.0,
        "unprocessed_payment_amount": 0.0,
    }


def demo_invoices(email: str) -> list:
    """A handful of invoices in varied statuses (paid / overdue / partial / sent)."""
    seed = _seed(email)
    base = 8500 + (seed % 4000)  # maintenance fee-ish amount
    now = datetime.utcnow()

    specs = [
        # (months_ago, status, sub_status, total, balance, color)
        (1, "overdue", "Overdue", base, base, "#C0392B"),
        (2, "partially_paid", "Partially Paid", base, base * 0.4, "#2F6DB5"),
        (3, "paid", "Paid", base, 0.0, "#2E7D32"),
        (4, "paid", "Paid", base, 0.0, "#2E7D32"),
        (0, "sent", "Sent", base, base, "#E08A1E"),
    ]
    invoices = []
    for idx, (months_ago, status, sub, total, balance, color) in enumerate(specs):
        date = now - timedelta(days=30 * months_ago)
        due = date + timedelta(days=14)
        invoices.append(
            _invoice(
                email=email,
                idx=idx,
                number=f"INV-{2026000 + seed % 1000 + idx}",
                status=status,
                sub_status=sub,
                total=total,
                balance=balance,
                date=date,
                due_date=due,
                color_code=color,
            )
        )
    return invoices


def demo_contact(user) -> dict:
    """A populated schemas.Contact-shaped dict for /users/me (with invoices)."""
    email = user.email
    seed = _seed(email)
    invoices = demo_invoices(email)
    outstanding = round(sum(i["balance"] for i in invoices), 2)
    local = (email.split("@")[0] if email and "@" in email else "Resident")
    first = local.replace(".", " ").replace("_", " ").title()
    now = datetime.utcnow()
    iso = now.isoformat()
    return {
        "contact_id": f"demo-{seed}",
        "contact_name": first,
        "customer_name": first,
        "vendor_name": "",
        "company_name": "Twickenham Glades",
        "website": "",
        "language_code": "en",
        "language_code_formatted": "English",
        "contact_type": "customer",
        "contact_type_formatted": "Customer",
        "status": "active",
        "customer_sub_type": "individual",
        "source": "demo",
        "is_linked_with_zohocrm": False,
        "payment_terms": 0,
        "payment_terms_label": "Due on Receipt",
        "currency_id": "",
        "twitter": "",
        "facebook": "",
        "currency_code": "JMD",
        "outstanding_receivable_amount": outstanding,
        "outstanding_receivable_amount_bcy": outstanding,
        "unused_credits_receivable_amount": 0.0,
        "unused_credits_receivable_amount_bcy": 0.0,
        "first_name": first,
        "last_name": "",
        "email": email,
        "phone": user.phone_number or "",
        "mobile": user.phone_number or "",
        "portal_status": "enabled",
        "portal_status_formatted": "Enabled",
        "created_time": now,
        "created_time_formatted": iso,
        "last_modified_time": now,
        "last_modified_time_formatted": iso,
        "custom_fields": [],
        "custom_field_hash": {},
        "ach_supported": False,
        "has_attachment": False,
        "address": demo_address(email),
        "invoices": invoices,
        "user_id": user.id,
        "delinquency_status": (
            user.resident.delinquency_status if getattr(user, "resident", None) else "INACTIVE"
        ),
    }

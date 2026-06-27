"""Shared payment finalize logic (used by the payments router + reconcile cron).

On a COMPLETED payment we: mark the row paid, reduce the matching cached
invoice, recompute the resident's standing (so the app/gate update instantly),
best-effort write the payment back to the accounting system, then push a receipt
+ broadcast + audit. Idempotent — safe to call twice for the same payment.
"""
from __future__ import annotations

import time

from sqlalchemy.orm import Session

from .. import models, push, audit
from ..enums import DelinquencyEnum
from ..realtime import publish_event
from ..logging_config import logger
from .lists import classify_from_balance, is_delinquent
from . import accounting


def recompute_resident_standing(db: Session, resident: "models.Resident") -> None:
    """Recompute outstanding balance + White/Yellow/Red + delinquency from the
    resident's cached invoices (no Zoho call needed)."""
    invoices = resident.cached_invoices or []
    outstanding = sum(float(inv.balance or 0) for inv in invoices)
    resident.outstanding_balance = outstanding
    category = classify_from_balance(outstanding, resident.on_payment_plan)
    resident.list_category = category
    resident.delinquency_status = (
        DelinquencyEnum.ACTIVE if is_delinquent(category) else DelinquencyEnum.INACTIVE
    )
    resident.updated_at = int(time.time())


def _apply_to_invoice(db: Session, payment: "models.Payment") -> None:
    if not payment.invoice_id:
        return
    inv = (db.query(models.CachedInvoice)
           .filter(models.CachedInvoice.resident_id == payment.resident_id,
                   models.CachedInvoice.invoice_id == payment.invoice_id)
           .first())
    if not inv:
        return
    inv.balance = max(0.0, float(inv.balance or 0) - float(payment.amount or 0))
    if inv.balance <= 0:
        inv.status = "paid"
    inv.last_payment_date = time.strftime("%Y-%m-%d")


def finalize_payment(db: Session, payment: "models.Payment", status: str,
                     provider_status: str | None = None, detail: str = "") -> "models.Payment":
    """Apply a provider-reported terminal status to a payment. Idempotent."""
    now = int(time.time())
    if provider_status:
        payment.provider_status = provider_status
    payment.updated_at = now

    # Terminal-but-not-success: just record it if still pending.
    if status in ("FAILED", "CANCELLED", "EXPIRED"):
        if payment.status == "PENDING":
            payment.status = status
        db.commit()
        return payment

    if status != "COMPLETED" or payment.status == "COMPLETED":
        db.commit()
        return payment

    # First time we see success → reconcile.
    payment.status = "COMPLETED"
    payment.paid_at = now
    _apply_to_invoice(db, payment)
    resident = payment.resident
    if resident:
        recompute_resident_standing(db, resident)
    db.commit()
    db.refresh(payment)

    # Best-effort write-back to the accounting system (reconciled at next sync otherwise).
    try:
        accounting.record_payment_best_effort(db, payment)
    except Exception as e:
        logger.warning("Write-back error for payment %s: %s", payment.id, e)

    # Receipt to the resident + live broadcast + audit (all best-effort).
    try:
        if resident and resident.user_id:
            tokens = push.tokens_for_user(db, str(resident.user_id))
            push.send_to_tokens(
                tokens, "Payment received",
                f"Your payment of {payment.currency} {payment.amount:,.2f} was received.",
                data={"type": "payment.completed", "id": str(payment.id)},
            )
    except Exception as e:
        logger.warning("Payment receipt push failed for %s: %s", payment.id, e)
    try:
        publish_event("payment.completed", payment.to_dict())
    except Exception as e:
        logger.warning("Payment SSE publish failed for %s: %s", payment.id, e)
    audit.record("payment.completed", actor_email=(resident.user.email if resident and resident.user else None),
                 detail=f"payment={payment.id} amount={payment.amount} provider={payment.provider}")
    logger.info("Payment %s COMPLETED (%s %.2f via %s)", payment.id, payment.currency,
                payment.amount or 0, payment.provider)
    return payment

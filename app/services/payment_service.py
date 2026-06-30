"""Shared payment finalize logic (used by the payments router + reconcile cron).

On a COMPLETED payment we: mark the row paid, reduce the matching cached
invoice, recompute the resident's standing (so the app/gate update instantly),
best-effort write the payment back to the accounting system, then push a receipt
+ broadcast + audit. Idempotent — safe to call twice for the same payment.
"""
from __future__ import annotations

import time

from sqlalchemy import text
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
    # Lock the invoice row so concurrent payments to the same invoice serialize.
    inv = (db.query(models.CachedInvoice)
           .filter(models.CachedInvoice.resident_id == payment.resident_id,
                   models.CachedInvoice.invoice_id == payment.invoice_id)
           .with_for_update()
           .first())
    if not inv:
        return
    inv.balance = max(0.0, float(inv.balance or 0) - float(payment.amount or 0))
    if inv.balance <= 0:
        inv.status = "paid"
    inv.last_payment_date = time.strftime("%Y-%m-%d")


def finalize_payment(db: Session, payment: "models.Payment", status: str,
                     provider_status: str | None = None, detail: str = "") -> "models.Payment":
    """Apply a provider-reported terminal status to a payment.

    Concurrency-safe: the provider return endpoint, the webhook, and the
    reconcile cron can all fire for the same payment at once. Completion is
    claimed with a single conditional UPDATE, so exactly one caller reconciles
    (reduces the invoice + recomputes standing); the others no-op.
    """
    now = int(time.time())

    # Terminal-but-not-success: record once, only if still pending (atomic).
    if status in ("FAILED", "CANCELLED", "EXPIRED"):
        db.query(models.Payment).filter(
            models.Payment.id == payment.id,
            models.Payment.status == "PENDING",
        ).update({"status": status, "provider_status": provider_status or payment.provider_status,
                  "updated_at": now}, synchronize_session=False)
        db.commit()
        db.refresh(payment)
        return payment

    if status != "COMPLETED":
        return payment  # nothing terminal to apply

    # Atomically claim completion. After the first committer, this conditional
    # UPDATE matches 0 rows for every other caller (Postgres READ COMMITTED),
    # so the invoice is never reduced twice.
    claimed = db.query(models.Payment).filter(
        models.Payment.id == payment.id,
        models.Payment.status != "COMPLETED",
    ).update({"status": "COMPLETED", "paid_at": now, "updated_at": now,
              "provider_status": provider_status or payment.provider_status},
             synchronize_session=False)
    db.commit()
    db.refresh(payment)
    if not claimed:
        return payment  # someone else already completed it — do not double-apply

    # Winner reconciles under a row lock on the resident (serializes concurrent
    # payments to the same resident) and the invoice row.
    # Lock the resident row with a raw statement (the ORM query eager-joins
    # visitors/tenants, and Postgres forbids FOR UPDATE across those outer
    # joins). The lock is held until this transaction commits, so concurrent
    # payments to the same resident recompute their standing one at a time.
    db.execute(text("SELECT 1 FROM residents WHERE id = :rid FOR UPDATE"),
               {"rid": str(payment.resident_id)})
    resident = (db.query(models.Resident)
                .filter(models.Resident.id == payment.resident_id)
                .first())
    _apply_to_invoice(db, payment)
    db.flush()  # ensure the invoice change is visible to recompute (autoflush is off)
    if resident:
        recompute_resident_standing(db, resident)

    # Capture everything the best-effort tail needs into plain locals BEFORE the
    # commit — commit expires the ORM objects, and touching a relationship after
    # would raise DetachedInstanceError.
    resident_user_id = str(resident.user_id) if resident and resident.user_id else None
    resident_email = resident.user.email if resident and resident.user else None
    snapshot = payment.to_dict()
    amount_str = f"{payment.currency} {payment.amount:,.2f}"
    pid_str = str(payment.id)
    db.commit()

    # Best-effort write-back to the accounting system. If it lands, mark the
    # payment reconciled so the daily sync trusts the accounting system for it;
    # if it doesn't, the sync re-applies it locally (reapply_unreconciled_payments).
    try:
        if accounting.record_payment_best_effort(db, payment):
            payment.applied_to_accounting = True
            db.commit()
    except Exception as e:
        logger.warning("Write-back error for payment %s: %s", pid_str, e)

    # Receipt to the resident + live broadcast + audit (all best-effort).
    try:
        if resident_user_id:
            tokens = push.tokens_for_user(db, resident_user_id)
            push.send_to_tokens(
                tokens, "Payment received",
                f"Your payment of {amount_str} was received.",
                data={"type": "payment.completed", "id": pid_str},
            )
    except Exception as e:
        logger.warning("Payment receipt push failed for %s: %s", pid_str, e)
    try:
        publish_event("payment.completed", snapshot)
    except Exception as e:
        logger.warning("Payment SSE publish failed for %s: %s", pid_str, e)
    audit.record("payment.completed", actor_email=resident_email,
                 detail=f"payment={pid_str} amount={snapshot.get('amount')} provider={snapshot.get('provider')}")
    logger.info("Payment %s COMPLETED (%s via %s)", pid_str, amount_str, snapshot.get("provider"))
    return payment


def reapply_unreconciled_payments(db: Session, resident: "models.Resident") -> None:
    """Run after a sync re-pulls invoices/standing from the accounting system.

    The daily sync overwrites a resident's cached invoices + outstanding balance
    from Zoho/QBO. An in-app payment that hasn't been written back there yet
    would otherwise revert the resident to unpaid (and possibly RED, re-blocking
    their visitors at the gate). So for each COMPLETED payment not yet reflected
    in accounting, we retry the write-back and, failing that, re-apply it locally
    — to the matching cached invoice and the resident's outstanding balance — and
    reclassify. This is drift-free: each sync resets from accounting first, so the
    payment is only ever subtracted once per cycle.
    """
    from . import accounting

    pays = (db.query(models.Payment)
            .filter(models.Payment.resident_id == resident.id,
                    models.Payment.status == "COMPLETED",
                    models.Payment.applied_to_accounting.is_(False))
            .all())
    if not pays:
        return

    unreconciled = 0.0
    for p in pays:
        # Retry the write-back; if it lands now, accounting reflects it → stop re-applying.
        try:
            if accounting.record_payment_best_effort(db, p):
                p.applied_to_accounting = True
                continue
        except Exception as e:
            logger.warning("Write-back retry failed for payment %s: %s", p.id, e)

        amount = float(p.amount or 0)
        unreconciled += amount
        if p.invoice_id:
            inv = (db.query(models.CachedInvoice)
                   .filter(models.CachedInvoice.resident_id == resident.id,
                           models.CachedInvoice.invoice_id == p.invoice_id)
                   .first())
            if inv and float(inv.balance or 0) >= amount:
                inv.balance = max(0.0, float(inv.balance) - amount)
                if inv.balance <= 0:
                    inv.status = "paid"

    if unreconciled > 0:
        resident.outstanding_balance = max(0.0, float(resident.outstanding_balance or 0) - unreconciled)
        category = classify_from_balance(resident.outstanding_balance, resident.on_payment_plan)
        resident.list_category = category
        resident.delinquency_status = (
            DelinquencyEnum.ACTIVE if is_delinquent(category) else DelinquencyEnum.INACTIVE
        )
        resident.updated_at = int(time.time())
        logger.info("Re-applied %d unreconciled payment(s) for resident %s (outstanding -%.2f)",
                    len(pays), resident.id, unreconciled)

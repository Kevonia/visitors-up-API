"""Reconcile PENDING in-app payments by polling the provider.

DimePay has no webhooks and a customer can close the browser before the return
redirect fires, so any payment left PENDING past a short grace is polled here and
finalized (or expired). Safe to run repeatedly; intended as a frequent cron:

    python scripts/reconcile_payments.py

Runs with the same PII_ENCRYPTION_KEY as the API (shared env group in prod).
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import SessionLocal  # noqa: E402
from app import models  # noqa: E402
from app.config.config import settings  # noqa: E402
from app.payments import get_provider, EXPIRED  # noqa: E402
from app.services.payment_service import finalize_payment  # noqa: E402
from app.logging_config import logger  # noqa: E402


def run() -> dict:
    db = SessionLocal()
    finalized = 0
    expired = 0
    errors = 0
    try:
        grace = max(0, settings.payment_pending_grace_minutes) * 60
        cutoff = int(time.time()) - grace
        pending = (db.query(models.Payment)
                   .filter(models.Payment.status == "PENDING",
                           models.Payment.created_at <= cutoff)
                   .all())
        for p in pending:
            try:
                provider = get_provider(p.provider)
                result = provider.poll_status(payment=p)
                if result.status == "PENDING":
                    # Still pending well past the grace → give up on it.
                    finalize_payment(db, p, EXPIRED, result.provider_status, "Expired after grace")
                    expired += 1
                else:
                    finalize_payment(db, p, result.status, result.provider_status, result.detail)
                    if p.status == "COMPLETED":
                        finalized += 1
            except Exception as e:
                errors += 1
                logger.error(f"Reconcile failed for payment {p.id}: {e}")
        logger.info(f"Payment reconcile: {finalized} finalized, {expired} expired, "
                    f"{errors} errors, {len(pending)} checked")
        return {"checked": len(pending), "finalized": finalized, "expired": expired, "errors": errors}
    finally:
        db.close()


if __name__ == "__main__":
    run()

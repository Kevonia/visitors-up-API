"""Accounting provider hooks (Zoho today; QuickBooks added in Phase 3).

For now this exposes the best-effort payment write-back used by the payments
finalize path. Real per-provider write-back + a full provider abstraction land
with the QuickBooks work; until then a payment is reconciled by the next sync.
"""
from __future__ import annotations

from ..config.config import settings
from ..logging_config import logger


def record_payment_best_effort(db, payment) -> bool:
    """Try to record an in-app payment against its invoice in the accounting
    system. Returns False if not possible (the next sync then reconciles)."""
    try:
        logger.info(
            "Accounting write-back for payment %s (%s %.2f) deferred to next %s sync",
            payment.id, payment.currency, payment.amount or 0, settings.accounting_provider,
        )
        return False
    except Exception as e:  # never break the payment finalize on a write-back error
        logger.warning("Accounting write-back failed for payment %s: %s", payment.id, e)
        return False

"""Accounting-provider abstraction (Zoho today; QuickBooks optional, coexisting).

`get_accounting_provider()` returns the active back-end based on
settings.accounting_provider. Both expose the same interface so the sync cron,
admin endpoints, and the payment write-back hook don't care which is in use. The
Zoho impl wraps the existing, unchanged code.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from ..config.config import settings
from ..logging_config import logger


class _ZohoAccounting:
    name = "zoho"

    def __init__(self):
        from ..zoho_integration.zoho_client import ZohoClient
        self.client = ZohoClient()

    def sync_resident(self, db: Session, resident) -> bool:
        from . import zoho_sync
        return zoho_sync.sync_resident(db, resident, self.client)

    def record_payment(self, db: Session, payment) -> bool:
        # Write-back to Zoho is deferred to the next sync (chosen fallback).
        return False

    def metrics(self) -> dict:
        return self.client.metrics()


class _QuickBooksAccounting:
    name = "quickbooks"

    def __init__(self):
        from ..quickbooks_integration.qb_client import QuickBooksClient
        self.client = QuickBooksClient()

    def sync_resident(self, db: Session, resident) -> bool:
        from . import qb_sync
        return qb_sync.sync_resident(db, resident, self.client)

    def record_payment(self, db: Session, payment) -> bool:
        return False

    def metrics(self) -> dict:
        return self.client.metrics()


def get_accounting_provider():
    """The active accounting provider instance."""
    if (settings.accounting_provider or "zoho").strip().lower() == "quickbooks":
        return _QuickBooksAccounting()
    return _ZohoAccounting()


def record_payment_best_effort(db, payment) -> bool:
    """Best-effort write-back of an in-app payment to the accounting system.
    Returns False (and the next sync reconciles) if not possible."""
    try:
        ok = get_accounting_provider().record_payment(db, payment)
        if not ok:
            logger.info(
                "Accounting write-back for payment %s deferred to next %s sync",
                payment.id, settings.accounting_provider)
        return ok
    except Exception as e:  # never break payment finalize on a write-back error
        logger.warning("Accounting write-back failed for payment %s: %s", payment.id, e)
        return False

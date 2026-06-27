"""Refresh every resident's dues/standing from the active accounting provider.

Dispatches via services.accounting.get_accounting_provider(), so it runs Zoho
(default) or QuickBooks depending on ACCOUNTING_PROVIDER — the cron command stays
the same. Replaces scripts/sync_zoho.py as the scheduled entrypoint.

    python scripts/sync_accounting.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import SessionLocal  # noqa: E402
from app import models  # noqa: E402
from app.config.config import settings  # noqa: E402
from app.services.accounting import get_accounting_provider  # noqa: E402
from app.logging_config import logger  # noqa: E402


def run() -> dict:
    db = SessionLocal()
    provider = get_accounting_provider()
    synced = errors = 0
    try:
        residents = db.query(models.Resident).all()
        for resident in residents:
            try:
                if provider.sync_resident(db, resident):
                    synced += 1
            except Exception as e:
                errors += 1
                logger.error(f"{provider.name} sync failed for resident {resident.id}: {e}")
        db.commit()
        total = len(residents)
        logger.info(f"{provider.name} sync complete: {synced} synced, {errors} errors, {total} residents")
        return {"provider": provider.name, "residents": total, "synced": synced, "errors": errors}
    finally:
        db.close()


if __name__ == "__main__":
    result = run()
    if result["residents"] and result["synced"] == 0 and result["errors"]:
        sys.exit(1)

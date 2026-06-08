"""Refresh every resident's payment list + delinquency from Zoho.

The list a resident is on (White / Yellow / Red) and their delinquency status can
change daily in Zoho, so this keeps the cached values on each resident fresh. It
is the same work as `POST /api/v1/admin/zoho/sync`, packaged as a standalone
command so a scheduler (e.g. a Render cron job) can run it without an admin
token:

    python scripts/sync_zoho.py

It is safe to run repeatedly and on every deploy. PII is encrypted at rest via
the ORM using PII_ENCRYPTION_KEY, so this MUST run with the same key as the API
(in production both share one env var group) or it would write unreadable data.
"""
import os
import sys

# Make `app` importable whether run as `python scripts/sync_zoho.py` or `-m`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import SessionLocal  # noqa: E402
from app import models  # noqa: E402
from app.zoho_integration.zoho_client import ZohoClient  # noqa: E402
from app.services.zoho_sync import sync_resident  # noqa: E402
from app.logging_config import logger  # noqa: E402


def run() -> dict:
    db = SessionLocal()
    zoho_client = ZohoClient()
    synced = 0
    errors = 0
    try:
        residents = db.query(models.Resident).all()
        for resident in residents:
            try:
                if sync_resident(db, resident, zoho_client):
                    synced += 1
            except Exception as e:  # keep going across the whole roster
                errors += 1
                logger.error(f"Zoho sync failed for resident {resident.id}: {e}")
        db.commit()
        total = len(residents)
        logger.info(
            f"Zoho sync complete: {synced} synced, {errors} errors, {total} residents")
        return {"residents": total, "synced": synced, "errors": errors}
    finally:
        db.close()


if __name__ == "__main__":
    result = run()
    # Non-zero exit if every resident failed (lets a scheduler flag the run).
    if result["residents"] and result["synced"] == 0 and result["errors"]:
        sys.exit(1)

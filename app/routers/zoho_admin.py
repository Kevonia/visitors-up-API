# app/routers/zoho_admin.py
"""Admin endpoints to keep resident delinquency in sync with Zoho in bulk,
inspect Zoho call/cache metrics, and bust the Zoho cache.

This is the mechanism that lets the hot paths (/users/me, the resident app)
serve delinquency from the database instead of querying Zoho per request.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models
from ..enums import RoleEnum
from ..utilities.db_util import get_db
from ..config.auth import require_roles
from ..zoho_integration.zoho_client import ZohoClient
from ..services.zoho_sync import sync_resident
from ..logging_config import logger

router = APIRouter()
zoho_client = ZohoClient()
_admin = require_roles(RoleEnum.ADMIN.value, RoleEnum.MANAGER.value)


@router.get("/zoho/metrics", dependencies=[Depends(_admin)])
def zoho_metrics():
    """Zoho API call count, cache hits and hit ratio (for tuning TTLs)."""
    return zoho_client.metrics()


@router.post("/zoho/sync", dependencies=[Depends(_admin)])
def sync_delinquency(db: Session = Depends(get_db)):
    """Refresh every resident's payment list + cached invoices from Zoho.

    Run on a schedule (or manually) so request paths never need a live Zoho
    fetch. Computes list_category (Yellow/Red/White) and caches invoices.
    """
    residents = db.query(models.Resident).all()
    synced = 0
    errors = 0
    for resident in residents:
        try:
            if sync_resident(db, resident, zoho_client):
                synced += 1
        except Exception as e:  # keep going across the whole roster
            errors += 1
            logger.error(f"Zoho sync failed for resident {resident.id}: {e}")
    db.commit()
    logger.info(f"Zoho sync complete: {synced} synced, {errors} errors")
    return {"residents": len(residents), "synced": synced, "errors": errors}


@router.post("/zoho/cache/bust", dependencies=[Depends(_admin)])
def bust_cache():
    """Invalidate all cached Zoho responses (forces fresh fetches)."""
    zoho_client.invalidate("zoho:cache:*")
    return {"detail": "Zoho cache invalidated"}

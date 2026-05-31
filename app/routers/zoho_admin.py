# app/routers/zoho_admin.py
"""Admin endpoints to keep resident delinquency in sync with Zoho in bulk,
inspect Zoho call/cache metrics, and bust the Zoho cache.

This is the mechanism that lets the hot paths (/users/me, the resident app)
serve delinquency from the database instead of querying Zoho per request.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models
from ..enums import RoleEnum, DelinquencyEnum
from ..utilities.db_util import get_db
from ..config.auth import require_roles
from ..zoho_integration.zoho_client import ZohoClient
from ..routers.auth import count_inactive_status
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
    """Recompute every resident's delinquency_status from Zoho invoices.

    Run on a schedule (or manually) so request paths never need a live
    full-invoice fetch.
    """
    residents = db.query(models.Resident).all()
    updated = 0
    errors = 0
    for resident in residents:
        try:
            user = resident.user
            if not user or not user.email:
                continue
            contact = zoho_client.get_contact_by_email(user.email)
            if not contact:
                continue
            invoices = zoho_client.get_invoices_for_contact(contact["contact_id"])
            overdue = count_inactive_status(invoices, "overdue")
            new_status = DelinquencyEnum.ACTIVE if overdue >= 3 else DelinquencyEnum.INACTIVE
            if resident.delinquency_status != new_status:
                resident.delinquency_status = new_status
                updated += 1
        except Exception as e:  # keep going across the whole roster
            errors += 1
            logger.error(f"Delinquency sync failed for resident {resident.id}: {e}")
    db.commit()
    logger.info(f"Zoho delinquency sync complete: {updated} updated, {errors} errors")
    return {"residents": len(residents), "updated": updated, "errors": errors}


@router.post("/zoho/cache/bust", dependencies=[Depends(_admin)])
def bust_cache():
    """Invalidate all cached Zoho responses (forces fresh fetches)."""
    zoho_client.invalidate("zoho:cache:*")
    return {"detail": "Zoho cache invalidated"}

# app/routers/zoho_admin.py
"""Admin endpoints to keep resident delinquency in sync with Zoho in bulk,
inspect Zoho call/cache metrics, and bust the Zoho cache.

This is the mechanism that lets the hot paths (/users/me, the resident app)
serve delinquency from the database instead of querying Zoho per request.
"""
from fastapi import APIRouter, Depends, HTTPException
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


@router.post("/zoho/sync/{resident_id}", dependencies=[Depends(_admin)])
def sync_one_resident(resident_id: str, db: Session = Depends(get_db)):
    """Refresh a single resident's payment list + cached invoices from Zoho.

    Powers the admin "Sync from Zoho" button so a specific resident can be
    corrected on demand without waiting for the daily job. Busts that
    resident's cached Zoho contact/invoices first so the pull is truly live.
    """
    resident = (
        db.query(models.Resident).filter(models.Resident.id == resident_id).first()
    )
    if not resident:
        raise HTTPException(status_code=404, detail="Resident not found")

    email = resident.user.email if resident.user else None
    if email:
        zoho_client.invalidate(
            f"zoho:cache:contact:{email.lower()}",
            f"zoho:cache:invoices:email:{email.lower()}",
        )
    if resident.zoho_contact_id:
        zoho_client.invalidate(
            f"zoho:cache:invoices:contact:{resident.zoho_contact_id}"
        )

    try:
        found = sync_resident(db, resident, zoho_client)
        db.commit()
        db.refresh(resident)
    except Exception as e:
        db.rollback()
        logger.error(f"Zoho sync failed for resident {resident_id}: {e}")
        raise HTTPException(status_code=502, detail="Zoho sync failed")

    if not found:
        raise HTTPException(
            status_code=404, detail="No matching Zoho contact for this resident"
        )

    return {
        "resident_id": str(resident.id),
        "list_category": resident.list_category.value if resident.list_category else None,
        "outstanding_balance": resident.outstanding_balance,
        "customer_status": resident.customer_status,
        "delinquency_status": (
            resident.delinquency_status.value if resident.delinquency_status else None
        ),
        "zoho_synced_at": resident.zoho_synced_at,
    }


@router.get("/residents/{resident_id}/invoices", dependencies=[Depends(_admin)])
def resident_invoices(resident_id: str, db: Session = Depends(get_db)):
    """A resident's invoices as cached from Zoho by the last sync.

    Read from our DB (populated by sync), so it's instant and needs no live
    Zoho call. Hit the per-resident sync first to refresh them.
    """
    resident = (
        db.query(models.Resident).filter(models.Resident.id == resident_id).first()
    )
    if not resident:
        raise HTTPException(status_code=404, detail="Resident not found")

    invoices = (
        db.query(models.CachedInvoice)
        .filter(models.CachedInvoice.resident_id == resident.id)
        .all()
    )
    # Open (still-owed) invoices first, then by due date.
    invoices.sort(key=lambda i: (float(i.balance or 0) <= 0, i.due_date or ""))
    return [
        {
            "invoice_id": i.invoice_id,
            "invoice_number": i.invoice_number,
            "status": i.status,
            "total": i.total,
            "balance": i.balance,
            "due_date": i.due_date,
            "date": i.date,
            "currency_code": i.currency_code,
            "company_name": i.company_name,
            "invoice_url": i.invoice_url,
        }
        for i in invoices
    ]


@router.post("/zoho/cache/bust", dependencies=[Depends(_admin)])
def bust_cache():
    """Invalidate all cached Zoho responses (forces fresh fetches)."""
    zoho_client.invalidate("zoho:cache:*")
    return {"detail": "Zoho cache invalidated"}

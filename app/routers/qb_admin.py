"""Admin management of the QuickBooks Online integration (mirror of zoho_admin).

Connect (OAuth), sync residents, metrics, cache-bust, status. Mounted under
/api/v1/admin. The OAuth callback is public (Intuit redirects to it, validated
by the state token); everything else requires ADMIN/MANAGER.
"""
import secrets

import redis
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from .. import models, audit
from ..config.config import settings
from ..config.auth import require_roles
from ..enums import RoleEnum
from ..utilities.db_util import get_db
from ..logging_config import logger
from ..quickbooks_integration.qb_client import QuickBooksClient, QuickBooksError
from ..services import qb_sync

router = APIRouter()
manager = require_roles(RoleEnum.ADMIN.value, RoleEnum.MANAGER.value)

_STATE_PREFIX = "qbo:oauth:state:"


def _redis():
    return redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)


@router.get("/quickbooks/status")
def qb_status(db: Session = Depends(get_db), _user=Depends(manager)):
    row = (db.query(models.IntegrationToken)
           .filter(models.IntegrationToken.provider == "quickbooks").first())
    return {
        "active_provider": settings.accounting_provider,
        "configured": bool(settings.qbo_client_id and settings.qbo_redirect_uri),
        "connected": bool(row and row.refresh_token and row.realm_id),
        "realm_id": row.realm_id if row else None,
        "env": settings.qbo_env,
    }


@router.get("/quickbooks/connect")
def qb_connect(_user=Depends(manager)):
    """Return the Intuit authorize URL for the admin to start the OAuth consent."""
    if not (settings.qbo_client_id and settings.qbo_redirect_uri):
        raise HTTPException(status_code=503, detail="QuickBooks is not configured.")
    state = secrets.token_urlsafe(24)
    try:
        _redis().set(_STATE_PREFIX + state, "1", ex=600)
    except redis.RedisError as e:
        logger.warning(f"Could not store QBO oauth state: {e}")
    return {"authorize_url": QuickBooksClient().authorize_url(state)}


@router.get("/quickbooks/callback", include_in_schema=False)
def qb_callback(code: str = "", realmId: str = "", state: str = ""):
    """Public OAuth redirect target. Validates state, exchanges the code, stores tokens."""
    ok = False
    try:
        r = _redis()
        ok = r.get(_STATE_PREFIX + state) == "1"
        if ok:
            r.delete(_STATE_PREFIX + state)
    except redis.RedisError:
        ok = False
    if not (code and realmId and ok):
        return HTMLResponse("<h3>QuickBooks connection failed.</h3>"
                            "<p>Invalid or expired request. Please try again from the admin.</p>",
                            status_code=400)
    try:
        QuickBooksClient().exchange_code(code=code, realm_id=realmId)
    except QuickBooksError as e:
        return HTMLResponse(f"<h3>QuickBooks connection failed.</h3><p>{e}</p>", status_code=400)
    audit.record("quickbooks.connected", detail=f"realm={realmId}")
    return HTMLResponse(
        "<h3 style='font-family:system-ui;color:#1E5631'>QuickBooks connected ✅</h3>"
        "<p style='font-family:system-ui'>You can close this tab and return to the admin.</p>")


@router.post("/quickbooks/sync")
def qb_sync_all(request: Request, db: Session = Depends(get_db), user=Depends(manager)):
    """Refresh every resident's customer + invoices from QuickBooks."""
    client = QuickBooksClient()
    synced = errors = 0
    residents = db.query(models.Resident).all()
    for resident in residents:
        try:
            if qb_sync.sync_resident(db, resident, client):
                synced += 1
        except Exception as e:
            errors += 1
            logger.error(f"QBO sync failed for resident {resident.id}: {e}")
    db.commit()
    audit.record("quickbooks.sync", user=user, request=request,
                 detail=f"synced={synced} errors={errors}")
    return {"residents": len(residents), "synced": synced, "errors": errors}


@router.get("/quickbooks/metrics")
def qb_metrics(_user=Depends(manager)):
    return QuickBooksClient().metrics()


@router.post("/quickbooks/cache/bust")
def qb_cache_bust(_user=Depends(manager)):
    QuickBooksClient().invalidate()
    return {"ok": True}

"""Background jobs executed by the RQ worker (`rq worker default`).

Each job owns its own DB session (never a request's). Kept import-light so the
worker process can import this module cheaply.
"""
from __future__ import annotations

from ..database import SessionLocal
from ..logging_config import logger


def refresh_resident_zoho(resident_id: str) -> None:
    """Refresh one resident's payment list/delinquency from Zoho (off the gate
    hot path). Best-effort; the daily cron is the backstop."""
    from .. import models
    from ..services.zoho_sync import sync_resident
    from ..zoho_integration.zoho_client import ZohoClient

    db = SessionLocal()
    try:
        r = db.query(models.Resident).filter(models.Resident.id == resident_id).first()
        if r and sync_resident(db, r, ZohoClient(), with_invoices=False):
            db.commit()
    except Exception as e:
        logger.warning("Background Zoho refresh failed for %s: %s", resident_id, e)
    finally:
        db.close()


def broadcast_residents_push(title: str, body: str, data: dict | None = None) -> None:
    """Send a push to every resident's devices (mass fan-out off the request)."""
    from .. import push

    db = SessionLocal()
    try:
        tokens = push.tokens_for_residents(db)
        push.send_to_tokens(tokens, title, body, data=data or {})
        logger.info("Broadcast push '%s' sent to %d tokens", title, len(tokens))
    except Exception as e:
        logger.warning("Broadcast push failed: %s", e)
    finally:
        db.close()

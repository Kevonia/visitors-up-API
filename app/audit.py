"""Persistent security audit trail.

`record()` writes one row to ``audit_logs`` per security-relevant action. It is
best-effort and isolated: it uses its own database session (never the caller's),
so an audit write can neither poison the request's transaction nor be rolled
back with it, and any failure is swallowed (logged) rather than raised into the
request path.

Usage:
    from app import audit
    audit.record("login.success", user=user, request=request)
    audit.record("login.failed", actor_email=username, status="failure",
                 request=request, detail="invalid_password")
"""
import time
from typing import Optional

from .database import SessionLocal
from . import models
from .logging_config import logger


def _client(request) -> tuple[Optional[str], Optional[str]]:
    """Pull (ip, user_agent) from a Starlette/FastAPI request, if present."""
    if request is None:
        return None, None
    ip = request.client.host if getattr(request, "client", None) else None
    try:
        ua = request.headers.get("user-agent")
    except Exception:
        ua = None
    return ip, ua


def record(
    action: str,
    *,
    user=None,
    actor_email: Optional[str] = None,
    status: str = "success",
    request=None,
    detail: Optional[str] = None,
) -> None:
    """Append one audit row. Safe to call from any request handler.

    Pass ``user`` (an ORM User) and/or an explicit ``actor_email`` (used for
    failed logins where no user matched). Identifiers are read into locals up
    front so nothing is lazily loaded across the dedicated session boundary.
    """
    user_id = getattr(user, "id", None)
    email = actor_email if actor_email is not None else getattr(user, "email", None)
    ip, ua = _client(request)

    db = SessionLocal()
    try:
        db.add(models.AuditLog(
            user_id=user_id,
            actor_email=email,
            action=action,
            status=status,
            ip=ip,
            user_agent=(ua[:500] if ua else None),
            detail=(detail[:1000] if detail else None),
            created_at=int(time.time()),
        ))
        db.commit()
    except Exception as e:  # never break the request being audited
        logger.error(f"audit record failed for '{action}': {e}")
        try:
            db.rollback()
        except Exception:
            pass
    finally:
        db.close()

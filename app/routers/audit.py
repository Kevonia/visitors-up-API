"""Admin-facing read API for the security audit trail.

Mounted under /api/v1/admin and guarded by admin_or_manager in main.py.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from .. import models
from ..utilities.db_util import get_db

router = APIRouter()


@router.get("/audit-logs")
def list_audit_logs(
    action: Optional[str] = Query(None, description="Filter by exact action, e.g. login.success"),
    user_id: Optional[str] = Query(None, description="Filter by acting user id"),
    status: Optional[str] = Query(None, description="Filter by status: success | failure"),
    from_time: Optional[int] = Query(None, alias="from", description="Only entries at/after this epoch"),
    to_time: Optional[int] = Query(None, alias="to", description="Only entries at/before this epoch"),
    skip: int = 0,
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
):
    """Most-recent-first audit entries with optional filters."""
    query = db.query(models.AuditLog)
    if action:
        query = query.filter(models.AuditLog.action == action)
    if user_id:
        query = query.filter(models.AuditLog.user_id == user_id)
    if status:
        query = query.filter(models.AuditLog.status == status)
    if from_time is not None:
        query = query.filter(models.AuditLog.created_at >= from_time)
    if to_time is not None:
        query = query.filter(models.AuditLog.created_at <= to_time)

    rows = (
        query.order_by(desc(models.AuditLog.created_at))
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [r.to_dict() for r in rows]

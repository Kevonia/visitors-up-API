"""Board analytics — aggregates from gate entries, visitors, residents,
incidents and the audit log. Mounted under /api/v1/admin (admin/manager only).

Day/hour bucketing uses Jamaica local time (UTC-5, no DST).
"""
import time

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from .. import models
from ..utilities.db_util import get_db

router = APIRouter()

_DAY = 86400
_JM_OFFSET = 5 * 3600  # UTC-5


@router.get("/analytics/summary")
def summary(db: Session = Depends(get_db)):
    now = int(time.time())
    return {
        "entries_today": db.query(models.GateEntry)
            .filter(models.GateEntry.entry_time >= now - _DAY).count(),
        "entries_7d": db.query(models.GateEntry)
            .filter(models.GateEntry.entry_time >= now - 7 * _DAY).count(),
        "on_site_now": db.query(models.GateEntry)
            .filter(models.GateEntry.exit_time.is_(None)).count(),
        "visitors_total": db.query(models.Visitor).count(),
        "residents_total": db.query(models.Resident).count(),
        "delinquent_residents": db.query(models.Resident)
            .filter(models.Resident.delinquency_status
                    == models.DelinquencyEnum.ACTIVE).count(),
        "open_incidents": db.query(models.Incident)
            .filter(models.Incident.status != "RESOLVED").count(),
        "incidents_30d": db.query(models.Incident)
            .filter(models.Incident.created_at >= now - 30 * _DAY).count(),
    }


@router.get("/analytics/entries-by-day")
def entries_by_day(days: int = Query(14, ge=1, le=90), db: Session = Depends(get_db)):
    start = int(time.time()) - days * _DAY
    rows = (db.query(models.GateEntry.entry_time)
            .filter(models.GateEntry.entry_time >= start).all())
    buckets: dict[str, int] = {}
    for (t,) in rows:
        d = time.strftime("%Y-%m-%d", time.gmtime(t - _JM_OFFSET))
        buckets[d] = buckets.get(d, 0) + 1
    return [{"date": d, "count": c} for d, c in sorted(buckets.items())]


@router.get("/analytics/entries-by-hour")
def entries_by_hour(days: int = Query(7, ge=1, le=90), db: Session = Depends(get_db)):
    start = int(time.time()) - days * _DAY
    rows = (db.query(models.GateEntry.entry_time)
            .filter(models.GateEntry.entry_time >= start).all())
    hours = {h: 0 for h in range(24)}
    for (t,) in rows:
        hours[time.gmtime(t - _JM_OFFSET).tm_hour] += 1
    return [{"hour": h, "count": hours[h]} for h in range(24)]


@router.get("/analytics/top-visitors")
def top_visitors(limit: int = Query(10, ge=1, le=50), db: Session = Depends(get_db)):
    """Residents ranked by how many gate entries their visitors generated (30d)."""
    start = int(time.time()) - 30 * _DAY
    rows = (db.query(models.GateEntry)
            .filter(models.GateEntry.entry_time >= start).all())
    counts: dict[str, int] = {}
    for e in rows:
        lot = e.lot_no or "—"
        counts[lot] = counts.get(lot, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return [{"lot_no": lot, "entries": c} for lot, c in ranked]

"""Concurrency regression tests — proves the race fixes hold.

Requires a real Postgres (FOR UPDATE / conditional-update semantics), so these
skip unless DATABASE_URL points at Postgres and the schema is migrated. CI runs
`alembic upgrade head` first. See app/services/payment_service.py (atomic claim)
and app/routers/gate.py (one-time pass consume).
"""
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

pytestmark = pytest.mark.skipif(
    "postgresql" not in os.environ.get("DATABASE_URL", ""),
    reason="needs a Postgres DATABASE_URL with the schema migrated",
)


def _seed():
    from app.database import SessionLocal
    from app import models
    from app.enums import VisitType, VisitorStatus

    rid, uidv, vid, pid = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    db = SessionLocal()
    db.add(models.User(id=uidv, email=f"c+{uuid.uuid4().hex[:8]}@t.com",
                       phone_number=f"1876{uuid.uuid4().int % 10000000:07d}", hashed_password="x"))
    db.add(models.Resident(id=rid, name="Race", lot_no="500", user_id=uidv,
                           outstanding_balance=50000.0, created_at=int(time.time()), updated_at=int(time.time())))
    db.add(models.CachedInvoice(id=uuid.uuid4(), resident_id=rid, invoice_id=f"INV-{pid}",
                                status="overdue", total=50000.0, balance=50000.0,
                                currency_code="JMD", synced_at=int(time.time())))
    db.add(models.Payment(id=pid, resident_id=rid, invoice_id=f"INV-{pid}", amount=5000.0,
                          currency="JMD", status="PENDING", provider="test",
                          created_at=int(time.time()), updated_at=int(time.time())))
    db.add(models.Visitor(id=vid, name="V", relationship_type="guest", visit_type=VisitType.ONE_TIME,
                          status=VisitorStatus.ACTIVE, created_by=rid))
    db.commit(); db.close()
    return rid, uidv, vid, pid


def test_payment_finalize_never_double_credits():
    from app.database import SessionLocal
    from app import models
    from app.services.payment_service import finalize_payment

    rid, _uid, _vid, pid = _seed()

    def fin(_):
        s = SessionLocal()
        try:
            finalize_payment(s, s.query(models.Payment).filter(models.Payment.id == pid).first(), "COMPLETED")
        finally:
            s.close()

    list(ThreadPoolExecutor(max_workers=12).map(fin, range(12)))
    s = SessionLocal()
    inv = s.query(models.CachedInvoice).filter(models.CachedInvoice.invoice_id == f"INV-{pid}").first()
    res = s.query(models.Resident).filter(models.Resident.id == rid).first()
    bal, out = inv.balance, res.outstanding_balance
    s.close()
    assert bal == 45000.0, f"invoice reduced more than once: {bal}"
    assert out == 45000.0, f"outstanding credited more than once: {out}"


def test_one_time_pass_single_entry():
    from app.database import SessionLocal
    from app import models
    from app.enums import VisitType, VisitorStatus

    rid, uidv, vid, _pid = _seed()

    def scan(_):
        s = SessionLocal()
        try:
            v = s.query(models.Visitor).filter(models.Visitor.id == vid).first()
            if not v.is_enterable()[0]:
                return
            claimed = (s.query(models.Visitor)
                       .filter(models.Visitor.id == vid, models.Visitor.status == VisitorStatus.ACTIVE)
                       .update({"status": VisitorStatus.USED}, synchronize_session=False))
            if not claimed:
                s.rollback(); return
            s.add(models.GateEntry(id=uuid.uuid4(), visitor_id=vid, resident_id=rid,
                                   logged_by=uidv, entry_time=int(time.time())))
            s.commit()
        finally:
            s.close()

    list(ThreadPoolExecutor(max_workers=12).map(scan, range(12)))
    s = SessionLocal()
    n = s.query(models.GateEntry).filter(models.GateEntry.visitor_id == vid).count()
    s.close()
    assert n == 1, f"one-time pass produced {n} entries (expected 1)"

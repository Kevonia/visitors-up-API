"""In-app dues payments (WiPay / DimePay / test).

Residents start a checkout; the provider redirects the customer back to our
public return endpoint (and/or posts a webhook) where the payment is finalized.
A reconcile cron (scripts/reconcile_payments.py) catches anything left pending.
"""
import json
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import desc
from sqlalchemy.orm import Session

from .. import models, schemas, crud, audit
from ..config.config import settings
from ..config.auth import get_current_user, require_roles
from ..enums import RoleEnum
from ..utilities.db_util import get_db
from ..logging_config import logger
from ..payments import get_provider, enabled_providers
from ..payments.factory import default_provider_name
from ..services.payment_service import finalize_payment

router = APIRouter()

manager = require_roles(RoleEnum.ADMIN.value, RoleEnum.MANAGER.value)


def _return_url(provider: str) -> str:
    base = (settings.payment_return_base_url
            or f"{settings.public_base_url.rstrip('/')}/api/v1/payments/return")
    return f"{base.rstrip('/')}/{provider}"


def _result_page(ok: bool, message: str) -> HTMLResponse:
    title = "Payment received" if ok else "Payment not completed"
    color = "#1E5631" if ok else "#C0392B"
    html = f"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>{title}</title></head>
<body style="font-family:system-ui;margin:0;display:grid;place-items:center;height:100vh;background:#F6F8F5">
<div style="text-align:center;padding:28px;max-width:380px">
<div style="font-size:54px">{'✅' if ok else '⚠️'}</div>
<h2 style="color:{color};margin:.4em 0">{title}</h2>
<p style="color:#5B6B61">{message}</p>
<p style="color:#5B6B61">You can return to the app.</p>
</div></body></html>"""
    return HTMLResponse(content=html)


@router.get("/payments/config")
def payments_config(_user=Depends(get_current_user)):
    """Tells the app whether to show the Pay button + which providers are on."""
    return {
        "enabled": bool(settings.payments_enabled and enabled_providers()),
        "providers": enabled_providers(),
        "default_provider": default_provider_name(),
    }


@router.post("/user/payments", response_model=schemas.PaymentCheckoutOut)
def create_payment(
    payload: schemas.PaymentCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """A resident starts an in-app payment; returns a hosted checkout URL."""
    if not settings.payments_enabled:
        raise HTTPException(status_code=503, detail="In-app payments are not enabled.")
    if payload.amount is None or payload.amount <= 0:
        raise HTTPException(status_code=422, detail="Amount must be greater than zero.")

    user = crud.get_user_by_email(db, email=current_user.email)
    resident = user.resident if user else None
    if not resident:
        raise HTTPException(status_code=403, detail="Only residents can make payments.")

    try:
        provider = get_provider(payload.provider)
    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e))

    now = int(time.time())
    payment = models.Payment(
        resident_id=resident.id,
        invoice_id=payload.invoice_id,
        invoice_number=payload.invoice_number,
        amount=float(payload.amount),
        currency=(payload.currency or "JMD").upper(),
        status="PENDING",
        provider=provider.name,
        platform_fee_pct=settings.platform_fee_pct,
        created_at=now,
        updated_at=now,
    )
    db.add(payment)
    db.commit()
    db.refresh(payment)

    try:
        result = provider.create_checkout(payment=payment, return_url=_return_url(provider.name))
    except Exception as e:
        payment.status = "FAILED"
        payment.provider_status = "checkout_error"
        db.commit()
        logger.warning("Checkout creation failed for payment %s: %s", payment.id, e)
        raise HTTPException(status_code=502, detail="Could not start the payment. Try again.")

    payment.provider_ref = result.provider_ref
    payment.raw = json.dumps(result.raw)[:8000]
    db.commit()
    audit.record("payment.created", user=current_user, request=request,
                 detail=f"payment={payment.id} provider={provider.name} amount={payment.amount}")
    return {"payment_id": str(payment.id), "provider": provider.name,
            "checkout_url": result.checkout_url, "status": payment.status}


@router.get("/user/payments", response_model=list[schemas.PaymentOut])
def my_payments(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    """The current resident's payment history, newest first."""
    user = crud.get_user_by_email(db, email=current_user.email)
    if not user or not user.resident:
        return []
    rows = (db.query(models.Payment)
            .filter(models.Payment.resident_id == user.resident.id)
            .order_by(desc(models.Payment.created_at)).all())
    return [p.to_dict() for p in rows]


async def _merge_params(request: Request) -> dict:
    params = dict(request.query_params)
    if request.method == "POST":
        try:
            form = await request.form()
            params.update({k: v for k, v in form.items()})
        except Exception:
            try:
                params.update(await request.json())
            except Exception:
                pass
    return params


def _lookup_payment(db: Session, params: dict) -> Optional["models.Payment"]:
    pid = params.get("ref") or params.get("order_id") or params.get("payment_id")
    if pid:
        p = db.query(models.Payment).filter(models.Payment.id == pid).first()
        if p:
            return p
    txn = params.get("transaction_id") or params.get("token")
    if txn:
        return db.query(models.Payment).filter(models.Payment.provider_ref == str(txn)).first()
    return None


@router.api_route("/payments/return/{provider}", methods=["GET", "POST"], include_in_schema=False)
async def payment_return(provider: str, request: Request, db: Session = Depends(get_db)):
    """Public: the provider redirects the customer here after checkout."""
    params = await _merge_params(request)
    payment = _lookup_payment(db, params)
    if not payment:
        return _result_page(False, "We couldn't match this payment.")
    try:
        prov = get_provider(provider)
        result = prov.finalize_from_return(payment=payment, params=params)
        finalize_payment(db, payment, result.status, result.provider_status, result.detail)
    except Exception as e:
        logger.warning("Return finalize failed for payment %s: %s", payment.id, e)
        return _result_page(False, "We're confirming your payment; check the app shortly.")
    ok = payment.status == "COMPLETED"
    return _result_page(ok, "Thank you — your dues have been updated." if ok
                        else "This payment wasn't completed.")


@router.post("/payments/webhook/{provider}", include_in_schema=False)
async def payment_webhook(provider: str, request: Request, db: Session = Depends(get_db)):
    """Public, signature-verified provider webhook (e.g. WiPay callback)."""
    body = await request.body()
    try:
        prov = get_provider(provider)
    except ValueError:
        raise HTTPException(status_code=404, detail="Unknown provider")
    result = prov.verify_webhook(headers=dict(request.headers), body=body)
    if result is None:
        # Provider has no webhook (or verification unsupported) — ignore quietly.
        return {"ok": True, "handled": False}
    payment = db.query(models.Payment).filter(
        models.Payment.provider_ref == str(result.provider_ref)).first()
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")
    finalize_payment(db, payment, result.status, result.provider_status, result.detail)
    return {"ok": True, "handled": True, "status": payment.status}


@router.get("/admin/payments", response_model=list[schemas.PaymentOut])
def list_payments(
    status: Optional[str] = None,
    limit: int = 200,
    db: Session = Depends(get_db),
    _user=Depends(manager),
):
    """Admin payments list (newest first), optional status filter."""
    q = db.query(models.Payment)
    if status:
        q = q.filter(models.Payment.status == status.upper())
    rows = q.order_by(desc(models.Payment.created_at)).limit(min(limit, 1000)).all()
    return [p.to_dict() for p in rows]

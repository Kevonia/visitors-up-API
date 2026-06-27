"""WiPay Jamaica — hosted redirect checkout.

Flow: POST a transaction request -> WiPay returns a hosted payment URL ->
customer pays -> WiPay redirects back to our return_url with status + a hash to
validate, and also posts a callback.

NOTE: WiPay's full field list + the exact response-hash formula are in their
request-gated PDF. The request fields and `md5(transaction_id+total+api_key)`
hash below follow WiPay's public plugin convention; confirm against the merchant
docs once credentials are issued. Until then this provider stays disabled.
"""
from __future__ import annotations

import httpx

from ..config.config import settings
from ..logging_config import logger
from .base import PaymentProvider, CheckoutResult, StatusResult, COMPLETED, FAILED, PENDING, md5_hash


def _first(d: dict, *keys, default=None):
    for k in keys:
        if isinstance(d, dict) and d.get(k) not in (None, ""):
            return d[k]
    return default


class WiPayProvider(PaymentProvider):
    name = "wipay"

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=httpx.Timeout(20.0))

    def create_checkout(self, *, payment, return_url: str) -> CheckoutResult:
        if not settings.wipay_account_number:
            raise RuntimeError("WiPay is not configured (WIPAY_ACCOUNT_NUMBER missing)")
        form = {
            "account_number": settings.wipay_account_number,
            "avs": "0",
            "country_code": settings.wipay_country,
            "currency": payment.currency or "JMD",
            "environment": settings.wipay_env,            # sandbox | live
            "fee_structure": "customer_pay",
            "order_id": str(payment.id),
            "origin": "vms",
            "response_url": return_url,
            "total": f"{payment.amount:.2f}",
        }
        url = f"{settings.wipay_base_url.rstrip('/')}/plugins/payments/request"
        with self._client() as c:
            resp = c.post(url, data=form)
            resp.raise_for_status()
            data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        checkout_url = _first(data, "url", "payment_url", "redirect_url")
        if not checkout_url:
            raise RuntimeError(f"WiPay did not return a checkout URL: {str(data)[:200]}")
        ref = _first(data, "transaction_id", "transaction_uid", default=str(payment.id))
        return CheckoutResult(checkout_url=checkout_url, provider_ref=str(ref), raw=data)

    def _verify_hash(self, params: dict) -> bool:
        # WiPay response hash convention; confirm field order against their docs.
        provided = str(_first(params, "hash", default=""))
        if not provided or not settings.wipay_api_key:
            return False
        txn = str(_first(params, "transaction_id", "transaction_uid", default=""))
        total = str(_first(params, "total", default=""))
        return md5_hash(txn, total, settings.wipay_api_key) == provided.lower()

    def finalize_from_return(self, *, payment, params: dict) -> StatusResult:
        status_raw = str(_first(params, "status", default="")).lower()
        if not self._verify_hash(params):
            logger.warning("WiPay return hash mismatch for payment %s", payment.id)
            return StatusResult(status=FAILED, detail="Hash verification failed",
                                provider_status=status_raw)
        ok = status_raw in ("success", "completed", "paid")
        return StatusResult(
            status=COMPLETED if ok else FAILED,
            detail=str(_first(params, "message", default="WiPay return")),
            provider_ref=str(_first(params, "transaction_id", default=payment.provider_ref or "")),
            provider_status=status_raw,
            raw=params,
        )

    def poll_status(self, *, payment) -> StatusResult:
        # WiPay relies on the return redirect + callback, not a polling API, so
        # we leave PENDING ones for the reconcile cron to expire after the grace.
        return StatusResult(status=PENDING, detail="WiPay has no poll endpoint",
                            provider_ref=payment.provider_ref)

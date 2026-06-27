"""DimePay — REST API (https://api.dimepay.app/dapi/v1), `client_key` auth.

Flow: create an order, open the hosted payment page, then read the order status
(DimePay documents no webhooks, so we confirm on the return redirect and via the
reconciliation poll). Endpoint/field names follow docs.dimepay.net; parsing is
defensive and should be confirmed once sandbox credentials are issued. Disabled
until DIMEPAY_CLIENT_KEY is set.
"""
from __future__ import annotations

import httpx

from ..config.config import settings
from ..logging_config import logger
from .base import PaymentProvider, CheckoutResult, StatusResult, COMPLETED, FAILED, PENDING, CANCELLED


def _first(d: dict, *keys, default=None):
    for k in keys:
        if isinstance(d, dict) and d.get(k) not in (None, ""):
            return d[k]
    return default


def _map_status(raw: str) -> str:
    s = (raw or "").strip().lower()
    if s in ("paid", "completed", "success", "successful", "captured", "settled"):
        return COMPLETED
    if s in ("failed", "declined", "error"):
        return FAILED
    if s in ("cancelled", "canceled", "voided", "expired"):
        return CANCELLED
    return PENDING


class DimePayProvider(PaymentProvider):
    name = "dimepay"

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=settings.dimepay_base_url.rstrip("/"),
            headers={"client_key": settings.dimepay_client_key,
                     "Content-Type": "application/json"},
            timeout=httpx.Timeout(20.0),
        )

    def create_checkout(self, *, payment, return_url: str) -> CheckoutResult:
        if not settings.dimepay_client_key:
            raise RuntimeError("DimePay is not configured (DIMEPAY_CLIENT_KEY missing)")
        with self._client() as c:
            order = c.post("/orders", json={
                "amount": round(payment.amount, 2),
                "currency": payment.currency or "JMD",
                "reference": str(payment.id),
                "return_url": return_url,
            })
            order.raise_for_status()
            odata = order.json()
            token = _first(odata, "token", "order_token", "id", "order_id")
            if not token:
                raise RuntimeError(f"DimePay order had no token: {str(odata)[:200]}")
            hosted = c.post("/payments/hosted-page", json={
                "token": token, "order_token": token, "return_url": return_url,
            })
            hosted.raise_for_status()
            hdata = hosted.json()
        checkout_url = _first(hdata, "url", "payment_url", "hosted_url", "redirect_url")
        if not checkout_url:
            raise RuntimeError(f"DimePay hosted-page had no URL: {str(hdata)[:200]}")
        return CheckoutResult(checkout_url=checkout_url, provider_ref=str(token), raw=odata)

    def _read_order(self, token: str) -> dict:
        with self._client() as c:
            resp = c.get(f"/orders/{token}")
            resp.raise_for_status()
            return resp.json()

    def _status_from_order(self, payment, data: dict) -> StatusResult:
        raw = str(_first(data, "status", "payment_status", "state", default=""))
        return StatusResult(status=_map_status(raw), detail=f"DimePay order {raw or 'unknown'}",
                            provider_ref=payment.provider_ref, provider_status=raw, raw=data)

    def finalize_from_return(self, *, payment, params: dict) -> StatusResult:
        token = payment.provider_ref or _first(params, "token", "order_token")
        if not token:
            return StatusResult(status=FAILED, detail="No DimePay order token")
        try:
            return self._status_from_order(payment, self._read_order(str(token)))
        except httpx.HTTPError as e:
            logger.warning("DimePay order read failed for %s: %s", payment.id, e)
            return StatusResult(status=PENDING, detail="DimePay status unavailable")

    def poll_status(self, *, payment) -> StatusResult:
        return self.finalize_from_return(payment=payment, params={})

"""First Data / Fiserv IPG "Connect" hosted-page provider (form POST + SHA-256).

Connect requires an HTML form POST to the gateway — not a GET redirect — so
`create_checkout` builds the signed fields, stashes them on the Payment (`raw`),
and returns a URL to our own bridge endpoint (`/payments/ipg/redirect/{id}`,
in routers/payments.py) which renders an auto-submitting form. The gateway
hosts the card page and POSTs the result back to `/payments/return/ipg`, where
`finalize_from_return` verifies the response hash and maps the status.

Spec: payment docs/IPG_IntegrationGuide_Connect_V2016-3.pdf.
Enable by setting IPG_STORE_NAME + IPG_SHARED_SECRET and adding `ipg` to
PAYMENTS_PROVIDERS. Test gateway + JMD (388) are the defaults; use even test
amounts (e.g. 13.00) — odd amounts can simulate a decline.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone as _tz

try:  # America/Jamaica is a fixed UTC-5 zone; fall back if tz db is missing.
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

from ..config.config import settings
from .base import PaymentProvider, CheckoutResult, StatusResult, COMPLETED, FAILED, PENDING


def _connect_hash(parts: str) -> str:
    """SHA-256 of the ASCII-hex representation of the joined values (Appendix I)."""
    hex_str = parts.encode("utf-8").hex()
    return hashlib.sha256(hex_str.encode("utf-8")).hexdigest()


class IPGProvider(PaymentProvider):
    name = "ipg"

    @property
    def store_name(self) -> str:
        return (settings.ipg_store_name or "").strip()

    @property
    def shared_secret(self) -> str:
        return settings.ipg_shared_secret or ""

    @property
    def gateway_url(self) -> str:
        return settings.ipg_gateway_url

    @property
    def currency(self) -> str:
        return str(settings.ipg_currency or "388")

    @property
    def timezone(self) -> str:
        return settings.ipg_timezone or "America/Jamaica"

    @property
    def mode(self) -> str:
        return settings.ipg_mode or "payonly"

    def _now(self) -> datetime:
        if ZoneInfo is not None:
            try:
                return datetime.now(ZoneInfo(self.timezone))
            except Exception:
                pass
        return datetime.now(_tz.utc)

    def _txndatetime(self) -> str:
        # IPG format: YYYY:MM:DD-HH:MM:SS
        return self._now().strftime("%Y:%m:%d-%H:%M:%S")

    def _request_hash(self, *, chargetotal: str, currency: str, txndatetime: str) -> str:
        # Appendix I: storename + txndatetime + chargetotal + currency + sharedsecret
        return _connect_hash(
            self.store_name + txndatetime + chargetotal + currency + self.shared_secret
        )

    def _response_hash(self, *, approval_code: str, chargetotal: str, currency: str,
                       txndatetime: str) -> str:
        # §12: sharedsecret + approval_code + chargetotal + currency + txndatetime + storename
        return _connect_hash(
            self.shared_secret + approval_code + chargetotal + currency
            + txndatetime + self.store_name
        )

    def create_checkout(self, *, payment, return_url: str) -> CheckoutResult:
        if not (self.store_name and self.shared_secret):
            raise RuntimeError("IPG is not configured (IPG_STORE_NAME / IPG_SHARED_SECRET).")

        chargetotal = f"{float(payment.amount):.2f}"
        currency = self.currency
        txndatetime = self._txndatetime()
        oid = str(payment.id)

        fields = {
            "txntype": "sale",
            "timezone": self.timezone,
            "txndatetime": txndatetime,
            "hash_algorithm": "SHA256",
            "hash": self._request_hash(
                chargetotal=chargetotal, currency=currency, txndatetime=txndatetime),
            "storename": self.store_name,
            "mode": self.mode,
            "chargetotal": chargetotal,
            "currency": currency,
            "oid": oid,
            "responseSuccessURL": return_url,
            "responseFailURL": return_url,
            "language": "en_US",
        }

        # The client opens this bridge URL; it renders the auto-POST form. We keep
        # the fields + the submitted txndatetime so the return can verify the hash.
        base = settings.public_base_url.rstrip("/")
        checkout_url = f"{base}/api/v1/payments/ipg/redirect/{oid}"
        raw = {
            "fields": fields,
            "gateway_url": self.gateway_url,
            "txndatetime": txndatetime,
            "chargetotal": chargetotal,
            "currency": currency,
        }
        return CheckoutResult(checkout_url=checkout_url, provider_ref=oid, raw=raw)

    def finalize_from_return(self, *, payment, params: dict) -> StatusResult:
        status = (params.get("status") or "").strip().upper()
        approval = (params.get("approval_code") or "").strip()
        received = (params.get("response_hash") or "").strip()

        stored = {}
        try:
            stored = json.loads(payment.raw or "{}")
        except Exception:
            stored = {}
        chargetotal = str(stored.get("chargetotal") or params.get("chargetotal") or "")
        currency = str(stored.get("currency") or params.get("currency") or "")

        # Verify the response hash against the submitted txndatetime; some gateway
        # profiles echo txndate_processed instead, so try both.
        verified = False
        if received and chargetotal and currency:
            candidates = {
                stored.get("txndatetime"),
                params.get("txndatetime"),
                params.get("txndate_processed"),
            }
            for txndt in filter(None, candidates):
                if self._response_hash(approval_code=approval, chargetotal=chargetotal,
                                       currency=currency, txndatetime=str(txndt)) == received:
                    verified = True
                    break

        approved = status == "APPROVED" or approval[:1].upper() == "Y"
        waiting = status not in ("APPROVED", "DECLINED", "FAILED") and approval[:1] == "?"

        if received and not verified:
            # A hash was sent but doesn't match — never trust it as paid.
            new_status = FAILED
            detail = "IPG response hash mismatch"
        elif approved:
            new_status = COMPLETED
            detail = "Approved"
        elif waiting:
            new_status = PENDING
            detail = "Awaiting confirmation"
        else:
            new_status = FAILED
            detail = params.get("fail_reason") or status or "Declined"

        return StatusResult(
            status=new_status,
            detail=detail,
            provider_ref=str(payment.id),
            provider_status=status or approval or None,
            raw={k: str(v) for k, v in params.items()},
        )

    def poll_status(self, *, payment) -> StatusResult:
        # Connect has no lightweight status poll (that needs the Web Service API);
        # the hosted-page return/notification is the source of truth. Leave PENDING.
        return StatusResult(status=PENDING, detail="IPG confirms via return/notification",
                            provider_ref=payment.provider_ref or str(payment.id))

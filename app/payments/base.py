"""Payment provider interface + shared helpers.

A provider turns a PENDING Payment into a hosted checkout, and later reports the
outcome — via the customer's return redirect, a webhook, or a status poll. All
providers map their own states onto the canonical statuses below.
"""
from __future__ import annotations

import hashlib
import hmac
from abc import ABC, abstractmethod
from typing import Optional

# Canonical payment statuses (mirror models.Payment.status).
PENDING = "PENDING"
COMPLETED = "COMPLETED"
FAILED = "FAILED"
CANCELLED = "CANCELLED"
EXPIRED = "EXPIRED"


class CheckoutResult:
    def __init__(self, checkout_url: str, provider_ref: Optional[str], raw: Optional[dict] = None):
        self.checkout_url = checkout_url
        self.provider_ref = provider_ref
        self.raw = raw or {}


class StatusResult:
    def __init__(self, status: str, detail: str = "", provider_ref: Optional[str] = None,
                 provider_status: Optional[str] = None, raw: Optional[dict] = None):
        self.status = status
        self.detail = detail
        self.provider_ref = provider_ref
        self.provider_status = provider_status
        self.raw = raw or {}


class PaymentProvider(ABC):
    """One payment processor. Stateless; reads settings + the Payment row."""
    name = "base"

    @abstractmethod
    def create_checkout(self, *, payment, return_url: str) -> CheckoutResult:
        """Create a hosted checkout for `payment`; return its URL + provider ref."""

    @abstractmethod
    def finalize_from_return(self, *, payment, params: dict) -> StatusResult:
        """Interpret the customer's return-redirect params into a status."""

    @abstractmethod
    def poll_status(self, *, payment) -> StatusResult:
        """Ask the provider for the current status (used by the reconcile cron)."""

    def verify_webhook(self, *, headers: dict, body: bytes) -> Optional[StatusResult]:
        """Verify + parse a provider webhook. Return None if unsupported."""
        return None


def verify_hmac(payload: str, signature: str, secret: str, algo=hashlib.sha256) -> bool:
    """Constant-time HMAC check for webhook/return signatures."""
    if not secret or not signature:
        return False
    expected = hmac.new(secret.encode(), payload.encode(), algo).hexdigest()
    return hmac.compare_digest(expected, signature.strip())


def md5_hash(*parts: str) -> str:
    """md5 of the concatenated parts (WiPay-style response hash)."""
    return hashlib.md5("".join(p or "" for p in parts).encode()).hexdigest()

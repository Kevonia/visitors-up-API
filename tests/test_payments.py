"""Unit tests for the payments provider abstraction (no DB / no network)."""
import os

# Enable a known provider set before importing the factory/settings.
os.environ.setdefault("PAYMENTS_PROVIDERS", "wipay,dimepay,test")
os.environ.setdefault("DEFAULT_PAYMENT_PROVIDER", "test")

import pytest

from app.payments import get_provider, enabled_providers, verify_hmac
from app.payments.base import md5_hash, COMPLETED, FAILED
from app.payments.wipay import WiPayProvider
from app.services.lists import classify_from_balance
from app.enums import ListCategory


class _FakePayment:
    def __init__(self, pid="p1", amount=1000.0, currency="JMD", provider_ref=None):
        self.id = pid
        self.amount = amount
        self.currency = currency
        self.provider_ref = provider_ref


def test_enabled_and_default_provider():
    assert set(enabled_providers()) == {"wipay", "dimepay", "test"}
    assert get_provider().name == "test"
    assert get_provider("wipay").name == "wipay"


def test_disabled_provider_raises():
    with pytest.raises(ValueError):
        get_provider("stripe")


def test_test_provider_round_trip():
    prov = get_provider("test")
    p = _FakePayment()
    co = prov.create_checkout(payment=p, return_url="http://x/return")
    assert "status=success" in co.checkout_url and co.provider_ref == "p1"
    assert prov.finalize_from_return(payment=p, params={"status": "success"}).status == COMPLETED
    assert prov.finalize_from_return(payment=p, params={"status": "fail"}).status == FAILED


def test_wipay_hash_validation(monkeypatch):
    from app.config.config import settings
    monkeypatch.setattr(settings, "wipay_api_key", "secret-key")
    prov = WiPayProvider()
    p = _FakePayment(amount=2500.0)
    good = md5_hash("txn-9", "2500.00", "secret-key")
    ok = prov.finalize_from_return(payment=p, params={
        "status": "success", "transaction_id": "txn-9", "total": "2500.00", "hash": good})
    assert ok.status == COMPLETED
    bad = prov.finalize_from_return(payment=p, params={
        "status": "success", "transaction_id": "txn-9", "total": "2500.00", "hash": "deadbeef"})
    assert bad.status == FAILED  # tampered hash rejected


def test_verify_hmac():
    import hmac, hashlib
    secret, body = "s3cr3t", "payload-body"
    sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    assert verify_hmac(body, sig, secret) is True
    assert verify_hmac(body, "nope", secret) is False
    assert verify_hmac(body, sig, "") is False


def test_classify_from_balance():
    assert classify_from_balance(0, "") == ListCategory.WHITE
    assert classify_from_balance(999_999, "") == ListCategory.RED
    assert classify_from_balance(999_999, "Y") == ListCategory.YELLOW

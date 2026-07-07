"""Select a payment provider by name, honoring the enabled set in settings."""
from __future__ import annotations

from functools import lru_cache

from ..config.config import settings
from .base import PaymentProvider
from .wipay import WiPayProvider
from .dimepay import DimePayProvider
from .test_provider import TestProvider
from .ipg import IPGProvider

_REGISTRY = {
    "wipay": WiPayProvider,
    "dimepay": DimePayProvider,
    "test": TestProvider,
    "ipg": IPGProvider,
}


def enabled_providers() -> list[str]:
    """Provider names turned on via PAYMENTS_PROVIDERS (csv), filtered to known ones."""
    raw = [p.strip().lower() for p in (settings.payments_providers or "").split(",")]
    return [p for p in raw if p in _REGISTRY]


def default_provider_name() -> str:
    name = (settings.default_payment_provider or "").strip().lower()
    enabled = enabled_providers()
    if name and name in enabled:
        return name
    return enabled[0] if enabled else ""


@lru_cache(maxsize=None)
def _instance(name: str) -> PaymentProvider:
    return _REGISTRY[name]()


def get_provider(name: str | None = None) -> PaymentProvider:
    """Return an enabled provider instance. Raises ValueError if not available."""
    chosen = (name or "").strip().lower() or default_provider_name()
    if not chosen:
        raise ValueError("No payment provider is enabled")
    if chosen not in enabled_providers():
        raise ValueError(f"Payment provider '{chosen}' is not enabled")
    return _instance(chosen)

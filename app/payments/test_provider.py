"""A simulated payment provider for development + credential-free verification.

`create_checkout` returns a URL pointing back at our own return endpoint with a
success marker, so the full flow (checkout -> return -> finalize -> invoice/
delinquency update -> receipt) can be exercised without any real processor.
Never enable in production.
"""
from __future__ import annotations

from .base import PaymentProvider, CheckoutResult, StatusResult, COMPLETED, FAILED


class TestProvider(PaymentProvider):
    name = "test"

    def create_checkout(self, *, payment, return_url: str) -> CheckoutResult:
        ref = str(payment.id)
        sep = "&" if "?" in return_url else "?"
        url = f"{return_url}{sep}provider=test&ref={ref}&status=success"
        return CheckoutResult(checkout_url=url, provider_ref=ref, raw={"simulated": True})

    def finalize_from_return(self, *, payment, params: dict) -> StatusResult:
        ok = str(params.get("status", "success")).lower() in ("success", "completed", "paid")
        return StatusResult(
            status=COMPLETED if ok else FAILED,
            detail="Simulated payment",
            provider_ref=str(payment.id),
            provider_status=str(params.get("status", "success")),
        )

    def poll_status(self, *, payment) -> StatusResult:
        # The simulated processor always reports success on poll.
        return StatusResult(status=COMPLETED, detail="Simulated payment (poll)",
                            provider_ref=payment.provider_ref or str(payment.id))

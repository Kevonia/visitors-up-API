"""Brevo (Sendinblue) HTTP transport for transactional email + SMS.

Low-level senders only. Higher-level helpers and the dev/prod transport switch
live in notifications/service.py.
"""
import httpx

from app.config.config import settings
from app.logging_config import logger

_EMAIL_URL = "https://api.brevo.com/v3/smtp/email"
_SMS_URL = "https://api.brevo.com/v3/transactionalSMS/sms"
_TIMEOUT = 10.0


def _headers() -> dict:
    return {
        "api-key": settings.brevo_api_key,
        "Content-Type": "application/json",
        "accept": "application/json",
    }


def brevo_send_email(to_email: str, to_name: str, subject: str, html: str) -> None:
    payload = {
        "sender": {
            "email": settings.brevo_sender_email,
            "name": settings.brevo_sender_name,
        },
        "to": [{"email": to_email, "name": to_name or to_email}],
        "subject": subject,
        "htmlContent": html,
    }
    try:
        resp = httpx.post(_EMAIL_URL, headers=_headers(), json=payload, timeout=_TIMEOUT)
        if resp.status_code >= 300:
            logger.warning(f"Brevo email to {to_email} failed: {resp.status_code} {resp.text}")
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Brevo email error for {to_email}: {exc}")


def brevo_send_sms(to_phone: str, text: str) -> None:
    phone = to_phone.strip()
    if not phone.startswith("+"):
        phone = "+" + phone.lstrip("0")
    payload = {
        "sender": settings.brevo_sms_sender,
        "recipient": phone,
        "content": text,
        "type": "transactional",
    }
    try:
        resp = httpx.post(_SMS_URL, headers=_headers(), json=payload, timeout=_TIMEOUT)
        if resp.status_code >= 300:
            logger.warning(f"Brevo SMS to {phone} failed: {resp.status_code} {resp.text}")
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Brevo SMS error for {phone}: {exc}")

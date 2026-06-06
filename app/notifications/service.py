"""Resident notification service: email + SMS with a dev/prod transport switch.

Transport is chosen by NOTIFICATIONS_TRANSPORT:
  - "brevo": send via the Brevo HTTP API (production).
  - "smtp":  send email to a local SMTP catcher (Mailpit) for dev testing, and
             deliver "SMS" as an email to the catcher too, so both show up in one
             inbox at http://localhost:8025 without needing a real SMS provider.

Everything is best-effort: failures are logged, never raised, so a notification
problem can't break the request. Call these from FastAPI BackgroundTasks.
"""
import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr

from app.config.config import settings
from app.logging_config import logger
from app.notifications import brevo


def _enabled() -> bool:
    if not settings.notifications_enabled:
        return False
    if settings.notifications_transport == "brevo":
        return bool(settings.brevo_api_key)
    return True  # smtp/dev needs no key


def _smtp_send(to_addr: str, subject: str, html: str) -> None:
    try:
        msg = MIMEText(html, "html")
        msg["Subject"] = subject
        msg["From"] = formataddr((settings.brevo_sender_name, settings.brevo_sender_email))
        msg["To"] = to_addr
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
            server.send_message(msg)
    except Exception as exc:  # noqa: BLE001
        logger.error(f"SMTP send error to {to_addr}: {exc}")


def send_email(to_email: str, to_name: str, subject: str, html: str) -> None:
    if not _enabled() or not to_email:
        return
    if settings.notifications_transport == "smtp":
        _smtp_send(to_email, subject, html)
    else:
        brevo.brevo_send_email(to_email, to_name, subject, html)


def send_sms(to_phone: str, text: str) -> None:
    if not _enabled() or not to_phone:
        return
    if settings.notifications_transport == "smtp":
        # No SMS catcher in dev — surface it as an email in Mailpit instead.
        _smtp_send(f"{to_phone}@sms.dev", f"[SMS] {to_phone}", f"<pre>{text}</pre>")
    else:
        brevo.brevo_send_sms(to_phone, text)


def notify_resident(email: str, phone: str, subject: str, message: str, html: str = None) -> None:
    """Send the same message to one resident by both email and SMS."""
    send_email(email, email, subject, html or f"<p>{message}</p>")
    send_sms(phone, message)


def notify_announcement(title: str, body: str) -> None:
    """Email + SMS every resident (USER role) about a new announcement."""
    if not _enabled():
        return
    from app.database import SessionLocal
    from app import models
    from app.enums import RoleEnum

    db = SessionLocal()
    try:
        residents = (
            db.query(models.User)
            .join(models.Role, models.User.role_id == models.Role.id)
            .filter(models.Role.name == RoleEnum.USER.value)
            .all()
        )
        subject = f"Twickenham Glades: {title}"
        html = f"<h3>{title}</h3><p>{body}</p>"
        sms = f"Twickenham Glades — {title}: {body}"[:300]
        for u in residents:
            notify_resident(u.email, u.phone_number, subject, sms, html=html)
        logger.info(f"Announcement notification sent to {len(residents)} resident(s).")
    finally:
        db.close()


def notify_guest_movement(email: str, phone: str, visitor_name: str, lot_no: str, event: str) -> None:
    """Notify a resident that their guest checked in / checked out.

    event is 'checked in' or 'checked out'.
    """
    if not _enabled():
        return
    subject = f"Visitor {event}: {visitor_name}"
    message = (
        f"Your visitor {visitor_name} {event} at the Twickenham Glades gate"
        f"{f' (Lot {lot_no})' if lot_no else ''}."
    )
    notify_resident(email, phone, subject, message)

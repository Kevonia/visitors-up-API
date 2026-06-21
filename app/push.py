"""Firebase Cloud Messaging (FCM HTTP v1) push sender.

Best-effort: never raises into the request path. Loads the service-account JSON
(``settings.firebase_credentials``), mints a short-lived OAuth2 access token via
google-auth, and POSTs to the FCM v1 endpoint. Tokens are sent one-by-one so a
single bad token doesn't sink the batch; tokens FCM reports as unregistered are
pruned from ``device_tokens``.

Usage:
    from app import push
    push.send_to_tokens(tokens, "New visitor", "Tap to view", data={"type": "visitor.created"})
    # token lookups (pass the caller's Session):
    push.tokens_for_user(db, user_id)
    push.tokens_for_guards(db)
"""
import base64
import json
import os
from typing import Optional

import requests
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import service_account

from .config.config import settings
from .database import SessionLocal
from . import models
from .enums import RoleEnum
from .logging_config import logger

_SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"]
_GUARD_ROLES = {RoleEnum.SECURITY.value, RoleEnum.ADMIN.value, RoleEnum.MANAGER.value}

_creds = None
_project_id = None


def _credentials():
    """Lazily load + cache the service-account credentials and project id.

    Prefers ``FIREBASE_CREDENTIALS_JSON`` (base64 of the key) so the credential
    lives in the persistent .env and survives a redeploy that wipes loose files;
    falls back to the JSON file at ``settings.firebase_credentials``.
    """
    global _creds, _project_id
    if _creds is None:
        b64 = os.environ.get("FIREBASE_CREDENTIALS_JSON")
        if b64:
            info = json.loads(base64.b64decode(b64))
        else:
            with open(settings.firebase_credentials) as f:
                info = json.load(f)
        _project_id = info.get("project_id")
        _creds = service_account.Credentials.from_service_account_info(info, scopes=_SCOPES)
    return _creds, _project_id


def send_to_tokens(tokens, title: str, body: str, data: Optional[dict] = None) -> None:
    """Send a notification to a list of FCM tokens. Best-effort; never raises."""
    tokens = [t for t in (tokens or []) if t]
    if not tokens:
        return
    try:
        creds, project_id = _credentials()
        creds.refresh(GoogleAuthRequest())
        bearer = creds.token
    except Exception as e:  # missing/invalid key, no network, etc.
        logger.error(f"FCM: could not obtain credentials/token: {e}")
        return

    url = f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"
    headers = {"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"}
    dead: list[str] = []
    for tok in tokens:
        msg = {"message": {"token": tok, "notification": {"title": title, "body": body}}}
        if data:
            msg["message"]["data"] = {k: str(v) for k, v in data.items()}
        try:
            resp = requests.post(url, headers=headers, data=json.dumps(msg), timeout=10)
            if resp.status_code == 200:
                continue
            text = resp.text.lower()
            # FCM reports a stale token as 404 UNREGISTERED or 400 INVALID_ARGUMENT.
            if resp.status_code == 404 or "unregistered" in text or "invalid-argument" in text \
                    or "registration-token-not-registered" in text:
                dead.append(tok)
            else:
                logger.warning(f"FCM send failed ({resp.status_code}): {resp.text[:200]}")
        except Exception as e:
            logger.warning(f"FCM send error: {e}")

    if dead:
        _prune_tokens(dead)


def _prune_tokens(tokens: list[str]) -> None:
    db = SessionLocal()
    try:
        db.query(models.DeviceToken).filter(
            models.DeviceToken.token.in_(tokens)
        ).delete(synchronize_session=False)
        db.commit()
        logger.info(f"FCM: pruned {len(tokens)} dead token(s)")
    except Exception as e:
        logger.error(f"FCM: prune failed: {e}")
        db.rollback()
    finally:
        db.close()


# --- token lookups (use the caller's Session) -------------------------------
def tokens_for_user(db, user_id) -> list[str]:
    rows = db.query(models.DeviceToken).filter(models.DeviceToken.user_id == user_id).all()
    return [r.token for r in rows]


def tokens_for_guards(db) -> list[str]:
    rows = (
        db.query(models.DeviceToken)
        .join(models.User, models.DeviceToken.user_id == models.User.id)
        .join(models.Role, models.User.role_id == models.Role.id)
        .filter(models.Role.name.in_(_GUARD_ROLES))
        .all()
    )
    return [r.token for r in rows]


def tokens_for_residents(db) -> list[str]:
    """All device tokens for resident (USER-role) accounts."""
    rows = (
        db.query(models.DeviceToken)
        .join(models.User, models.DeviceToken.user_id == models.User.id)
        .join(models.Role, models.User.role_id == models.Role.id)
        .filter(models.Role.name == RoleEnum.USER.value)
        .all()
    )
    return [r.token for r in rows]

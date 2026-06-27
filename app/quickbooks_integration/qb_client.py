# quickbooks_integration/qb_client.py
"""QuickBooks Online client — the QBO counterpart to ZohoClient.

Mirrors the Zoho pattern (Redis-cached access token, httpx + retry/backoff,
filtered queries, metrics) with QBO's differences:
- OAuth2 with Intuit; the **refresh token rotates** on every refresh and is
  stored in the `integration_tokens` table (not env), so we persist the new one.
- Calls are scoped to a company via the realm id and use QBO's SQL-like query API.
Obtain the initial refresh token + realm id via the admin Connect flow (qb_admin).
"""
import base64
import json
import time
import logging

import httpx
import redis

from app.config.config import settings
from app.database import SessionLocal
from app import models

logger = logging.getLogger(__name__)

TOKEN_KEY = "qbo:access_token"
TOKEN_TTL = 3300
METRIC_CALLS = "qbo:metrics:api_calls"
METRIC_CACHE_HITS = "qbo:metrics:cache_hits"

CUSTOMER_TTL = 6 * 3600
INVOICE_TTL = 3600

AUTHORIZE_URL = "https://appcenter.intuit.com/connect/oauth2"
TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
SCOPE = "com.intuit.quickbooks.accounting"


class QuickBooksError(Exception):
    pass


class QuickBooksClient:
    def __init__(self):
        self._redis = redis.Redis.from_url(
            settings.REDIS_URL, max_connections=10, decode_responses=True)
        self._http = httpx.Client(timeout=httpx.Timeout(20.0))

    # -- config -------------------------------------------------------------
    def base_url(self) -> str:
        if settings.qbo_base_url:
            return settings.qbo_base_url.rstrip("/")
        return ("https://quickbooks.api.intuit.com"
                if settings.qbo_env == "production"
                else "https://sandbox-quickbooks.api.intuit.com")

    def _basic_auth(self) -> str:
        raw = f"{settings.qbo_client_id}:{settings.qbo_client_secret}".encode()
        return base64.b64encode(raw).decode()

    # -- token / credential persistence ------------------------------------
    def _creds(self):
        """(refresh_token, realm_id) from the integration_tokens row, or (None, None)."""
        db = SessionLocal()
        try:
            row = (db.query(models.IntegrationToken)
                   .filter(models.IntegrationToken.provider == "quickbooks").first())
            return (row.refresh_token, row.realm_id) if row else (None, None)
        finally:
            db.close()

    def save_tokens(self, *, refresh_token: str, realm_id: str = None,
                    access_token: str = None, expires_in: int = 3600) -> None:
        """Upsert the QBO credentials (rotating refresh token) + cache the access token."""
        db = SessionLocal()
        try:
            row = (db.query(models.IntegrationToken)
                   .filter(models.IntegrationToken.provider == "quickbooks").first())
            now = int(time.time())
            if not row:
                row = models.IntegrationToken(provider="quickbooks", created_at=now)
                db.add(row)
            if refresh_token:
                row.refresh_token = refresh_token
            if realm_id:
                row.realm_id = realm_id
            if access_token:
                row.access_token = access_token
            row.updated_at = now
            db.commit()
        finally:
            db.close()
        if access_token:
            try:
                self._redis.set(TOKEN_KEY, access_token, ex=max(int(expires_in) - 300, 60))
            except redis.RedisError as e:
                logger.error(f"Redis error storing QBO token: {e}")

    def _get_token(self) -> str:
        try:
            tok = self._redis.get(TOKEN_KEY)
            if tok:
                return tok
        except redis.RedisError as e:
            logger.error(f"Redis error reading QBO token: {e}")
        return self.refresh_access_token()

    def refresh_access_token(self) -> str:
        refresh_token, _ = self._creds()
        if not refresh_token:
            raise QuickBooksError("QuickBooks is not connected (no refresh token).")
        resp = self._http.post(
            TOKEN_URL,
            headers={"Authorization": f"Basic {self._basic_auth()}",
                     "Accept": "application/json",
                     "Content-Type": "application/x-www-form-urlencoded"},
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        )
        if resp.status_code != 200:
            logger.error(f"QBO token refresh failed: {resp.status_code} {resp.text}")
            raise QuickBooksError("Failed to refresh QuickBooks access token")
        body = resp.json()
        # The refresh token rotates — persist the new one.
        self.save_tokens(refresh_token=body.get("refresh_token", refresh_token),
                         access_token=body["access_token"],
                         expires_in=int(body.get("expires_in", 3600)))
        logger.info("Refreshed QuickBooks access token")
        return body["access_token"]

    def exchange_code(self, *, code: str, realm_id: str) -> None:
        """OAuth callback: swap the authorization code for tokens + store them."""
        resp = self._http.post(
            TOKEN_URL,
            headers={"Authorization": f"Basic {self._basic_auth()}",
                     "Accept": "application/json",
                     "Content-Type": "application/x-www-form-urlencoded"},
            data={"grant_type": "authorization_code", "code": code,
                  "redirect_uri": settings.qbo_redirect_uri},
        )
        if resp.status_code != 200:
            logger.error(f"QBO code exchange failed: {resp.status_code} {resp.text}")
            raise QuickBooksError("QuickBooks authorization failed")
        body = resp.json()
        self.save_tokens(refresh_token=body["refresh_token"], realm_id=realm_id,
                         access_token=body["access_token"],
                         expires_in=int(body.get("expires_in", 3600)))

    def authorize_url(self, state: str) -> str:
        from urllib.parse import urlencode
        return AUTHORIZE_URL + "?" + urlencode({
            "client_id": settings.qbo_client_id,
            "response_type": "code",
            "scope": SCOPE,
            "redirect_uri": settings.qbo_redirect_uri,
            "state": state,
        })

    # -- low-level query ----------------------------------------------------
    def _incr(self, key):
        try:
            self._redis.incr(key)
        except redis.RedisError:
            pass

    def query(self, statement: str) -> list:
        """Run a QBO SQL-like query and return the entity rows."""
        _, realm_id = self._creds()
        if not realm_id:
            raise QuickBooksError("QuickBooks is not connected (no realm id).")
        token = self._get_token()
        url = f"{self.base_url()}/v3/company/{realm_id}/query"
        params = {"query": statement, "minorversion": settings.qbo_minor_version}
        backoff = 0.5
        for attempt in range(4):
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            try:
                self._incr(METRIC_CALLS)
                resp = self._http.get(url, headers=headers, params=params)
            except httpx.HTTPError as e:
                logger.warning(f"QBO transport error ({attempt}): {e}")
                time.sleep(backoff); backoff *= 2; continue
            if resp.status_code == 401:
                token = self.refresh_access_token(); continue
            if resp.status_code == 429 or resp.status_code >= 500:
                time.sleep(backoff); backoff *= 2; continue
            if resp.status_code != 200:
                raise QuickBooksError(f"QBO {resp.status_code}: {resp.text[:200]}")
            qr = resp.json().get("QueryResponse", {})
            # The entity key is whatever was selected (Customer / Invoice / ...).
            for k, v in qr.items():
                if isinstance(v, list):
                    return v
            return []
        raise QuickBooksError("QuickBooks API is currently unavailable.")

    @staticmethod
    def _escape(value: str) -> str:
        return (value or "").replace("'", "\\'")

    def get_customer_by_email(self, email: str):
        key = f"qbo:cache:customer:{email.lower()}"
        try:
            raw = self._redis.get(key)
            if raw is not None:
                self._incr(METRIC_CACHE_HITS)
                return json.loads(raw) or None
        except (redis.RedisError, json.JSONDecodeError):
            pass
        rows = self.query(
            f"select * from Customer where PrimaryEmailAddr = '{self._escape(email)}'")
        customer = rows[0] if rows else None
        try:
            self._redis.set(key, json.dumps(customer or {}), ex=CUSTOMER_TTL)
        except redis.RedisError:
            pass
        return customer

    def get_invoices_for_customer(self, customer_id: str):
        key = f"qbo:cache:invoices:{customer_id}"
        try:
            raw = self._redis.get(key)
            if raw is not None:
                self._incr(METRIC_CACHE_HITS)
                return json.loads(raw)
        except (redis.RedisError, json.JSONDecodeError):
            pass
        rows = self.query(
            f"select * from Invoice where CustomerRef = '{self._escape(str(customer_id))}'")
        try:
            self._redis.set(key, json.dumps(rows), ex=INVOICE_TTL)
        except redis.RedisError:
            pass
        return rows

    def invalidate(self, *patterns: str):
        try:
            for pattern in patterns or ("qbo:cache:*",):
                for k in self._redis.scan_iter(match=pattern):
                    self._redis.delete(k)
        except redis.RedisError as e:
            logger.error(f"QBO cache invalidate error: {e}")

    def metrics(self) -> dict:
        try:
            calls = int(self._redis.get(METRIC_CALLS) or 0)
            hits = int(self._redis.get(METRIC_CACHE_HITS) or 0)
        except redis.RedisError:
            calls, hits = 0, 0
        total = calls + hits
        return {"api_calls": calls, "cache_hits": hits,
                "cache_hit_ratio": round(hits / total, 3) if total else 0.0}

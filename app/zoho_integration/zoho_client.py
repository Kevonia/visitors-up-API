# zoho_integration/zoho_client.py
"""Resilient Zoho Invoice client.

Improvements over the original:
- Access token is shared across workers via Redis (key ``zoho:access_token``)
  and refreshed proactively, not just reactively on a 401.
- Uses ``httpx`` with timeouts + retry/backoff on 429/5xx.
- Typed, *filtered* helpers (``?email=`` / ``?customer_id=``) so we stop pulling
  the entire contact and invoice lists and scanning them in Python.
- Per-resource response caching in Redis, plus lightweight call/cache metrics.
"""
import json
import time
import logging

import httpx
import redis

from fastapi import HTTPException, status
from app.config.config import settings

logger = logging.getLogger(__name__)

# Redis keys
TOKEN_KEY = "zoho:access_token"
TOKEN_TTL = 3300  # refresh a little before Zoho's ~3600s expiry
METRIC_CALLS = "zoho:metrics:api_calls"
METRIC_CACHE_HITS = "zoho:metrics:cache_hits"

# Cache TTLs (seconds)
CONTACT_TTL = 3 * 3600  # keep list-category source data ≤3h stale (see zoho_cache_ttl)
ADDRESS_TTL = 6 * 3600
INVOICE_TTL = 3600
ALL_CONTACTS_TTL = 3 * 3600  # full-roster contact pull; refreshed at most every 3h
PAYMENTS_TTL = 1800           # full customer-payments pull; refreshed at most every 30m

_TOKEN_URL = "https://accounts.zoho.com/oauth/v2/token"


class ZohoClient:
    def __init__(self):
        self.zoho_api_url = settings.zoho_api_url
        self._redis = redis.Redis.from_url(
            settings.REDIS_URL, max_connections=10, decode_responses=True
        )
        self._http = httpx.Client(timeout=httpx.Timeout(15.0))

    # -- token management ---------------------------------------------------
    def _get_token(self) -> str:
        """Return a cached access token, seeding from .env or refreshing as needed."""
        try:
            token = self._redis.get(TOKEN_KEY)
            if token:
                return token
        except redis.RedisError as e:
            logger.error(f"Redis error reading Zoho token: {e}")

        # Seed once from the env-provided token, then rely on refresh.
        if settings.access_token:
            self._store_token(settings.access_token)
            return settings.access_token
        return self.refresh_access_token()

    def _store_token(self, token: str, ttl: int = TOKEN_TTL):
        try:
            self._redis.set(TOKEN_KEY, token, ex=ttl)
        except redis.RedisError as e:
            logger.error(f"Redis error storing Zoho token: {e}")

    def refresh_access_token(self) -> str:
        payload = {
            "refresh_token": settings.refresh_token,
            "client_id": settings.client_id,
            "client_secret": settings.client_secret,
            "grant_type": "refresh_token",
        }
        resp = self._http.post(_TOKEN_URL, data=payload)
        if resp.status_code != 200:
            logger.error(f"Zoho token refresh failed: {resp.status_code} {resp.text}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to refresh Zoho access token",
            )
        body = resp.json()
        token = body["access_token"]
        ttl = int(body.get("expires_in", 3600)) - 300
        self._store_token(token, ttl=max(ttl, 60))
        logger.info("Refreshed Zoho access token")
        return token

    # -- low-level request --------------------------------------------------
    def make_request(self, endpoint, method="GET", data=None, params=None):
        """Call the Zoho API with auth, retry/backoff and a single 401 refresh."""
        url = f"{self.zoho_api_url}/{endpoint}"
        token = self._get_token()
        backoff = 0.5

        # Zoho Invoice requires the organization id on every call.
        if settings.zoho_org_id:
            params = {**(params or {}), "organization_id": settings.zoho_org_id}

        for attempt in range(4):
            headers = {
                "Authorization": f"Zoho-oauthtoken {token}",
                "Content-Type": "application/json",
            }
            try:
                self._incr(METRIC_CALLS)
                resp = self._http.request(method, url, headers=headers, json=data, params=params)
            except httpx.HTTPError as e:
                logger.warning(f"Zoho transport error ({attempt}): {e}")
                time.sleep(backoff)
                backoff *= 2
                continue

            if resp.status_code == 401:  # token expired -> refresh once and retry
                token = self.refresh_access_token()
                continue
            if resp.status_code == 429 or resp.status_code >= 500:
                logger.warning(f"Zoho {resp.status_code}; retrying in {backoff}s")
                time.sleep(backoff)
                backoff *= 2
                continue
            if resp.status_code not in (200, 201):
                raise HTTPException(status_code=resp.status_code, detail=resp.text)
            return resp.json()

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Zoho API is currently unavailable. Please try again later.",
        )

    # -- caching helpers ----------------------------------------------------
    def _incr(self, key: str):
        try:
            self._redis.incr(key)
        except redis.RedisError:
            pass

    def _cache_get(self, key: str):
        try:
            raw = self._redis.get(key)
            if raw is not None:
                self._incr(METRIC_CACHE_HITS)
                return json.loads(raw)
        except (redis.RedisError, json.JSONDecodeError) as e:
            logger.error(f"Zoho cache read error for {key}: {e}")
        return None

    def _cache_set(self, key: str, value, ttl: int):
        try:
            self._redis.set(key, json.dumps(value), ex=ttl)
        except redis.RedisError as e:
            logger.error(f"Zoho cache write error for {key}: {e}")

    def invalidate(self, *patterns: str):
        """Delete cached Zoho keys (used by the admin sync/cache-bust)."""
        try:
            for pattern in patterns or ("zoho:cache:*",):
                for k in self._redis.scan_iter(match=pattern):
                    self._redis.delete(k)
        except redis.RedisError as e:
            logger.error(f"Zoho cache invalidate error: {e}")

    # -- filtered, cached resource accessors --------------------------------
    def get_contact_by_email(self, email: str):
        """Fetch a single contact via the server-side ``?email=`` filter."""
        key = f"zoho:cache:contact:{email.lower()}"
        cached = self._cache_get(key)
        if cached is not None:
            return cached or None
        data = self.make_request("contacts", params={"email": email})
        contacts = data.get("contacts", []) if isinstance(data, dict) else []
        contact = next(
            (c for c in contacts if c.get("email", "").lower() == email.lower()),
            contacts[0] if contacts else None,
        )
        self._cache_set(key, contact or {}, CONTACT_TTL)
        return contact

    def get_all_contacts(self):
        """Every Zoho contact (paged, 200/page), cached in Redis so the roster
        endpoints don't re-page the whole contact list on every request."""
        key = "zoho:cache:contacts:all"
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        contacts, page = [], 1
        while True:
            data = self.make_request("contacts", params={"page": page, "per_page": 200})
            if not isinstance(data, dict):
                break
            contacts.extend(data.get("contacts", []))
            if not data.get("page_context", {}).get("has_more_page"):
                break
            page += 1
        self._cache_set(key, contacts, ALL_CONTACTS_TTL)
        return contacts

    def get_contact_address(self, contact_id: str):
        key = f"zoho:cache:address:{contact_id}"
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        data = self.make_request(f"contacts/{contact_id}/address")
        addresses = data.get("addresses", []) if isinstance(data, dict) else []
        self._cache_set(key, addresses, ADDRESS_TTL)
        return addresses

    def get_invoices_for_contact(self, contact_id: str):
        key = f"zoho:cache:invoices:contact:{contact_id}"
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        data = self.make_request("invoices", params={"customer_id": contact_id})
        invoices = data.get("invoices", []) if isinstance(data, dict) else []
        self._cache_set(key, invoices, INVOICE_TTL)
        return invoices

    def get_invoices_by_email(self, email: str):
        key = f"zoho:cache:invoices:email:{email.lower()}"
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        data = self.make_request("invoices", params={"email": email})
        invoices = data.get("invoices", []) if isinstance(data, dict) else []
        self._cache_set(key, invoices, INVOICE_TTL)
        return invoices

    def get_all_payments(self):
        """Every Zoho customer payment (paged, 200/page), cached in Redis.

        Used by the admin Payments view so payments recorded directly in Zoho
        (not just in-app checkouts) show up as transactions and count toward
        collections."""
        key = "zoho:cache:payments:all"
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        payments, page = [], 1
        while True:
            data = self.make_request(
                "customerpayments", params={"page": page, "per_page": 200}
            )
            if not isinstance(data, dict):
                break
            payments.extend(data.get("customerpayments", []))
            if not data.get("page_context", {}).get("has_more_page"):
                break
            page += 1
        self._cache_set(key, payments, PAYMENTS_TTL)
        return payments

    def metrics(self) -> dict:
        try:
            calls = int(self._redis.get(METRIC_CALLS) or 0)
            hits = int(self._redis.get(METRIC_CACHE_HITS) or 0)
        except redis.RedisError:
            calls, hits = 0, 0
        total = calls + hits
        return {
            "api_calls": calls,
            "cache_hits": hits,
            "cache_hit_ratio": round(hits / total, 3) if total else 0.0,
        }

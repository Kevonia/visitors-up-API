"""Reusable Redis rate limiting (same approach as the login limiter in auth.py).

Fail-open: if Redis is unavailable we allow the request rather than block a
paying resident over an infrastructure hiccup. Counters are simple INCR + TTL.
"""
from __future__ import annotations

import redis
from fastapi import HTTPException, Request

from ..config.config import settings
from ..logging_config import logger

_pool = redis.ConnectionPool.from_url(settings.REDIS_URL, max_connections=10)


def client_ip(request: Request) -> str:
    """Real client IP — behind Caddy/EC2 the first X-Forwarded-For entry."""
    xff = request.headers.get("x-forwarded-for") if request else None
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request and request.client else "unknown"


def _allowed(key: str, limit: int, window_seconds: int) -> bool:
    try:
        conn = redis.Redis(connection_pool=_pool)
        n = conn.incr(key)
        if n == 1:
            conn.expire(key, window_seconds)
        return n <= limit
    except Exception as e:  # never block on a Redis problem
        logger.warning("Rate limit check failed (allowing): %s", e)
        return True


def enforce(request: Request, *, action: str, limit: int, window_seconds: int,
            by: str = "ip", subject: str | None = None) -> None:
    """Raise 429 if `action` exceeds `limit` per `window_seconds`.

    by="ip" keys on the caller's IP; pass by="user"/subject=<id> to key on a
    resident/user instead.
    """
    ident = subject or (client_ip(request) if by == "ip" else "global")
    if not _allowed(f"rl:{action}:{by}:{ident}", limit, window_seconds):
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please slow down and try again shortly.",
        )

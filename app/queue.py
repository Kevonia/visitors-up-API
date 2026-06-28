"""Lightweight background queue on the existing Redis (RQ).

Used to move slow/fan-out work off the request path — a stale-cache Zoho refresh
at the gate, and mass push notifications. Enqueue is best-effort: if Redis/RQ is
unavailable the caller falls back to running the work inline, so a Redis blip
never breaks a request.
"""
from __future__ import annotations

import redis
from rq import Queue

from .config.config import settings
from .logging_config import logger

_queue = None


def get_queue():
    global _queue
    if _queue is None:
        conn = redis.Redis.from_url(settings.REDIS_URL)
        _queue = Queue("default", connection=conn)
    return _queue


def enqueue(func, *args, **kwargs) -> bool:
    """Enqueue a job. Returns True if queued, False if the caller should run it
    inline (queue unavailable)."""
    try:
        get_queue().enqueue(func, *args, **kwargs)
        return True
    except Exception as e:
        logger.warning("RQ enqueue failed (%s); running inline instead", e)
        return False

"""Live gate updates over Server-Sent Events (SSE), fanned out via Redis pub/sub.

When a resident registers a visitor, the create endpoint PUBLISHes a small event
to a Redis channel. Guard apps hold an SSE connection to ``/api/v1/gate/events``
and receive it within milliseconds. Going through Redis (rather than an in-memory
list of connections) means the event reaches a guard no matter which web worker
or instance served the resident's POST — important on Render's multi-instance
setup, where the guard and the resident may be talking to different processes.

The payload carries only what a guard is already authorised to see in gate
search (visitor name, lot, resident name). It lives in Redis transiently for the
pub/sub delivery and is never persisted here.
"""
import json

import redis
import redis.asyncio as aioredis

from app.config.config import settings
from app.logging_config import logger

VISITOR_EVENTS_CHANNEL = "gate:visitor_events"

# How often (seconds) to emit a heartbeat comment when no event arrives, so the
# connection survives idle-timeout proxies and the client can detect a drop.
_HEARTBEAT_SECONDS = 15.0

# One shared sync pool for fire-and-forget publishes from request handlers.
_pub_pool = redis.ConnectionPool.from_url(
    settings.REDIS_URL, max_connections=5, decode_responses=True
)


def publish_event(event: str, data: dict) -> None:
    """Best-effort publish of an SSE event. Never raises into the request path —
    a Redis hiccup must not break visitor creation."""
    try:
        conn = redis.Redis(connection_pool=_pub_pool)
        try:
            conn.publish(
                VISITOR_EVENTS_CHANNEL,
                json.dumps({"event": event, "data": data}, default=str),
            )
        finally:
            conn.close()
    except Exception as e:  # noqa: BLE001 — deliberately swallow all Redis errors
        logger.warning(f"SSE publish failed for '{event}': {e}")


async def _aclose(obj) -> None:
    """Close a redis.asyncio object across library versions (aclose vs close)."""
    try:
        closer = getattr(obj, "aclose", None) or getattr(obj, "close", None)
        if closer is not None:
            await closer()
    except Exception:  # noqa: BLE001
        pass


async def event_stream(request):
    """Async generator yielding SSE frames from the Redis channel.

    Stops when the client disconnects. Emits a heartbeat comment every
    ``_HEARTBEAT_SECONDS`` so idle connections stay open.
    """
    r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe(VISITOR_EVENTS_CHANNEL)
    try:
        # An initial comment opens the stream immediately for the client.
        yield ": connected\n\n"
        while True:
            if await request.is_disconnected():
                break
            message = await pubsub.get_message(
                ignore_subscribe_messages=True, timeout=_HEARTBEAT_SECONDS
            )
            if message and message.get("type") == "message":
                try:
                    payload = json.loads(message["data"])
                except (ValueError, TypeError):
                    continue
                event = payload.get("event", "message")
                data = json.dumps(payload.get("data", {}))
                yield f"event: {event}\ndata: {data}\n\n"
            else:
                # No event within the window — keep the connection warm.
                yield ": keep-alive\n\n"
    finally:
        await _aclose(pubsub)
        await _aclose(r)

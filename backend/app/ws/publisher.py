"""
WebSocket event publisher — writes events to the Redis pub/sub channel.

Usage from any backend module:
    from app.ws.publisher import publish_event
    await publish_event(redis_client, org_id, "violation.detected", {...})

The connection_manager's Redis listener will fan it out to all connected clients.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


async def publish_event(
    redis_client: Any,
    org_id: int,
    event_type: str,
    payload: dict[str, Any],
) -> None:
    """
    Publish a live event to the org's Redis channel.
    Fails silently if Redis is unavailable (non-blocking, fail-open).
    """
    if redis_client is None:
        return
    try:
        message = json.dumps({
            "event": event_type,
            "ts": datetime.now(timezone.utc).isoformat(),
            "org_id": org_id,
            **payload,
        })
        await redis_client.publish(f"compliance:live:{org_id}", message)
    except Exception as e:
        logger.warning("WS publish failed (non-critical)", event=event_type, error=str(e))

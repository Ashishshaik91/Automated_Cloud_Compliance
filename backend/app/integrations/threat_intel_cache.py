"""
Redis-backed threat intel cache.

TTL: 24 hours (86400 seconds).
Key format: ti:{source}:{query_hash}

Designed as a thin async wrapper around redis.asyncio.
Falls back gracefully to no-cache (returns None) if Redis is unavailable.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

_CACHE_TTL = 86_400  # 24 hours in seconds


def _make_key(source: str, query: str) -> str:
    """Generate a stable Redis cache key from source name and query string."""
    query_hash = hashlib.sha256(query.encode()).hexdigest()[:16]
    return f"ti:{source}:{query_hash}"


async def cache_get(
    redis_client: Any,
    source: str,
    query: str,
) -> Any | None:
    """
    Retrieve a cached threat intel result.

    Returns:
        Deserialized value if cache hit, None on miss or Redis error.
    """
    if redis_client is None:
        return None

    key = _make_key(source, query)
    try:
        raw = await redis_client.get(key)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as e:
        logger.warning("Threat intel cache GET failed", key=key, error=str(e))
        return None


async def cache_set(
    redis_client: Any,
    source: str,
    query: str,
    value: Any,
) -> None:
    """
    Store a threat intel result in Redis with 24h TTL.

    Silently fails if Redis is unavailable.
    """
    if redis_client is None:
        return

    key = _make_key(source, query)
    try:
        serialized = json.dumps(value, default=str)
        await redis_client.setex(key, _CACHE_TTL, serialized)
    except Exception as e:
        logger.warning("Threat intel cache SET failed", key=key, error=str(e))


async def cache_invalidate(
    redis_client: Any,
    source: str,
    query: str,
) -> None:
    """Delete a specific cache entry (e.g. after a manual refresh)."""
    if redis_client is None:
        return

    key = _make_key(source, query)
    try:
        await redis_client.delete(key)
    except Exception as e:
        logger.warning("Threat intel cache DELETE failed", key=key, error=str(e))

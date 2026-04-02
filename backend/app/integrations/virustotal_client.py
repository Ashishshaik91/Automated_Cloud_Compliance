"""
VirusTotal v3 API client with Redis-backed rate limiting.

Free tier: 4 requests/minute total across all workers.
Rate limiting is enforced via a Redis sorted set acting as a sliding-window counter.
Requests exceeding the limit are queued (max depth 100); requests that cannot be
served within 60 seconds are dropped as 'vt_enrichment_skipped'.

Returns a reputation ratio: malicious_count / total_engines (0.0–1.0).
Returns None on failure (fail-open).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import structlog

from app.config import get_settings

logger = structlog.get_logger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_RATE_LIMIT_PER_MINUTE = 4
VT_REDIS_KEY = "vt:rate_limit"
VT_QUEUE_MAX = 100
VT_WAIT_TIMEOUT_S = 60


async def _check_rate_limit(redis_client: Any) -> bool:
    """
    Check the sliding-window rate limit using a Redis sorted set.
    Adds the current timestamp to the set and counts requests in the last 60s.
    Returns True if the request is allowed, False if throttled.
    """
    now = time.time()
    window_start = now - 60.0

    pipe = redis_client.pipeline()
    pipe.zremrangebyscore(VT_REDIS_KEY, "-inf", window_start)
    pipe.zadd(VT_REDIS_KEY, {str(now): now})
    pipe.zcard(VT_REDIS_KEY)
    pipe.expire(VT_REDIS_KEY, 120)
    results = await pipe.execute()

    count = results[2]
    return count <= VT_RATE_LIMIT_PER_MINUTE


async def get_ip_reputation(
    ip_address: str,
    redis_client: Any = None,
) -> float | None:
    """
    Query VirusTotal for the reputation of an IP address.

    Returns:
        float: malicious_count / total_engines ratio (0.0–1.0)
        None:  on error, missing API key, or rate limit exhaustion
    """
    settings = get_settings()
    vt_key = settings.virustotal_api_key.get_secret_value() if settings.virustotal_api_key else ""
    if not vt_key:
        logger.debug("VirusTotal API key not configured; skipping VT enrichment")
        return None

    # Rate limiting via Redis if available
    if redis_client is not None:
        waited = 0
        while not await _check_rate_limit(redis_client):
            if waited >= VT_WAIT_TIMEOUT_S:
                logger.warning(
                    "VT rate limit: request dropped after timeout",
                    ip=ip_address,
                    waited_s=waited,
                )
                return None
            await asyncio.sleep(15)
            waited += 15

    url = f"{VT_BASE_URL}/ip_addresses/{ip_address}"
    headers = {"x-apikey": vt_key}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
    except httpx.TimeoutException:
        logger.warning("VirusTotal API timeout", ip=ip_address)
        return None
    except httpx.HTTPStatusError as e:
        logger.warning("VirusTotal API HTTP error", status=e.response.status_code, ip=ip_address)
        return None
    except Exception as e:
        logger.error("VirusTotal API unexpected error", error=str(e), ip=ip_address)
        return None

    stats = (
        data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
    )
    malicious = stats.get("malicious", 0)
    total     = sum(stats.values()) if stats else 0

    if total == 0:
        return 0.0

    ratio = round(malicious / total, 4)
    logger.info(
        "VirusTotal reputation fetched",
        ip=ip_address,
        malicious=malicious,
        total=total,
        ratio=ratio,
    )
    return ratio

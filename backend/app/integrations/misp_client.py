"""
MISP (Malware Information Sharing Platform) client.

Disabled by default — only enabled when MISP_URL is set in config.
Queries a MISP instance for threat events matching resource IPs or tags.

Returns a list of {event_id, info, threat_level, tags} dicts.
Returns [] when disabled or on failure (fail-open).
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.config import get_settings

logger = structlog.get_logger(__name__)


def _is_enabled() -> bool:
    """Returns True only if MISP_URL is configured."""
    settings = get_settings()
    return bool(settings.misp_url)


async def search_misp_events(
    value: str,
    search_type: str = "ip-dst",
) -> list[dict[str, Any]]:
    """
    Search a MISP instance for events matching the given value.

    Args:
        value:       IP address, hostname, or tag to search for.
        search_type: MISP attribute type ('ip-dst', 'ip-src', 'domain', etc.).

    Returns:
        List of matching MISP event summaries.
        Returns [] if MISP is disabled or any error occurs.
    """
    if not _is_enabled():
        return []

    settings = get_settings()
    misp_url  = settings.misp_url.rstrip("/")
    misp_key  = settings.misp_api_key.get_secret_value() if settings.misp_api_key else ""

    if not misp_key:
        logger.warning("MISP_URL is set but MISP_API_KEY is missing; MISP enrichment disabled")
        return []

    headers = {
        "Authorization": misp_key,
        "Accept":        "application/json",
        "Content-Type":  "application/json",
    }
    payload = {
        "returnFormat": "json",
        "type":         search_type,
        "value":        value,
        "limit":        20,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:  # noqa: S501
            response = await client.post(
                f"{misp_url}/events/restSearch",
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()
    except httpx.TimeoutException:
        logger.warning("MISP API timeout", value=value)
        return []
    except Exception as e:
        logger.error("MISP API error", error=str(e), value=value)
        return []

    events = data.get("response", [])
    results = []
    for event_wrapper in events:
        event = event_wrapper.get("Event", {})
        results.append({
            "event_id":     event.get("id"),
            "info":         event.get("info", ""),
            "threat_level": event.get("threat_level_id"),  # 1=High, 2=Med, 3=Low, 4=Undefined
            "tags":         [t.get("name") for t in event.get("Tag", [])],
            "date":         event.get("date"),
        })

    logger.info("MISP search complete", value=value, matches=len(results))
    return results

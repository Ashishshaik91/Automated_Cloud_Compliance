"""
Threat Intelligence API — feed health, on-demand enrichment, cached CVE lookup.

Endpoints:
  GET  /api/v1/threat-intel/health          — feed reachability + cache stats
  POST /api/v1/threat-intel/enrich          — trigger immediate enrichment (admin)
  GET  /api/v1/threat-intel/cve/{resource_type} — cached CVE list for a type
  POST /api/v1/threat-intel/cache/invalidate    — force cache bust (admin)
"""

from __future__ import annotations

from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import AdminUser, CurrentUser
from app.auth.scoping import get_org_scope, require_write_access
from app.models.database import get_db

router = APIRouter()
logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Feed health
# ---------------------------------------------------------------------------

@router.get(
    "/health",
    summary="Threat intel feed health check",
    response_model=dict,
)
async def threat_intel_health(
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, Any]:
    """
    Probe each configured threat intel feed and report availability.
    Returns NVD, VirusTotal, MISP and Redis cache status.
    Available to all authenticated users.
    """
    from app.core.threat_intel_task import check_feed_health

    # Best-effort Redis connection (not strictly required for health check)
    redis_client = None
    try:
        import redis.asyncio as aioredis
        from app.config import get_settings
        settings = get_settings()
        redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    except Exception:
        pass

    health = await check_feed_health(redis_client)
    if redis_client:
        try:
            await redis_client.aclose()
        except Exception:
            pass
    return health


# ---------------------------------------------------------------------------
# On-demand enrichment (admin)
# ---------------------------------------------------------------------------

@router.post(
    "/enrich",
    summary="Trigger immediate threat intel enrichment",
    response_model=dict,
)
async def trigger_enrichment(
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    dspm: bool = Query(True, description="Enrich stale DSPM findings"),
    violations: bool = Query(True, description="Enrich open violations with CVE data"),
) -> dict[str, Any]:
    """
    Trigger an immediate threat intel enrichment run.

    Re-enriches DSPM findings and/or violations that are stale or un-enriched.
    Equivalent to running the Celery beat task on demand.
    Admin only.
    """
    from app.core.threat_intel_task import (
        enrich_stale_dspm_findings,
        enrich_open_violations,
    )

    redis_client = None
    try:
        import redis.asyncio as aioredis
        from app.config import get_settings
        settings = get_settings()
        redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    except Exception:
        pass

    results: dict[str, Any] = {"status": "ok"}

    async with db.begin():
        if dspm:
            results["dspm"] = await enrich_stale_dspm_findings(db, redis_client)
        if violations:
            results["violations"] = await enrich_open_violations(db, redis_client)

    if redis_client:
        try:
            await redis_client.aclose()
        except Exception:
            pass

    logger.info("On-demand enrichment complete", results=results, triggered_by=current_user.id)
    return results


# ---------------------------------------------------------------------------
# CVE lookup by resource type
# ---------------------------------------------------------------------------

@router.get(
    "/cve/{resource_type}",
    summary="Get cached CVE list for a cloud resource type",
    response_model=dict,
)
async def get_cves_for_resource(
    resource_type: str,
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    force_refresh: bool = Query(False, description="Bypass cache and re-fetch from NVD"),
) -> dict[str, Any]:
    """
    Return NVD CVEs for the given resource type (e.g. 's3', 'rds', 'blob').
    Results are Redis-cached for 24h. Set force_refresh=true to bypass cache.
    """
    from app.integrations.nvd_client import query_nvd_cpe, get_cpe_for_resource
    from app.integrations.threat_intel_cache import cache_get, cache_set, cache_invalidate

    # Sanitise input — only allow known resource types
    safe_rtype = resource_type.lower().strip().replace(" ", "_")[:64]
    cpe = get_cpe_for_resource(safe_rtype)

    if not cpe:
        raise HTTPException(
            status_code=400,
            detail=f"No CPE mapping found for resource type '{safe_rtype}'. "
                   "Supported types: s3, rds, ec2_instance, iam_user, blob, gcs, bigquery.",
        )

    redis_client = None
    try:
        import redis.asyncio as aioredis
        from app.config import get_settings
        settings = get_settings()
        redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    except Exception:
        pass

    cves: list[dict] = []
    cache_hit = False

    if not force_refresh and redis_client:
        cached = await cache_get(redis_client, "nvd", safe_rtype)
        if cached is not None:
            cves = cached
            cache_hit = True

    if not cache_hit:
        cves = await query_nvd_cpe(safe_rtype)
        if redis_client:
            await cache_set(redis_client, "nvd", safe_rtype, cves)

    if redis_client:
        try:
            await redis_client.aclose()
        except Exception:
            pass

    return {
        "resource_type": safe_rtype,
        "cpe":           cpe,
        "cve_count":     len(cves),
        "cache_hit":     cache_hit,
        "cves":          cves,
    }


# ---------------------------------------------------------------------------
# Cache invalidation (admin)
# ---------------------------------------------------------------------------

@router.post(
    "/cache/invalidate",
    summary="Invalidate threat intel cache entries",
    response_model=dict,
)
async def invalidate_cache(
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    source: str = Query("nvd", description="Feed source: 'nvd', 'virustotal', or 'misp'"),
    query: str = Query(..., description="Cache query key (e.g. resource type or IP)"),
) -> dict[str, Any]:
    """
    Bust a specific threat intel cache entry by source and query key.
    Forces the next enrichment run to re-fetch from the external feed.
    Admin only.
    """
    from app.integrations.threat_intel_cache import cache_invalidate

    valid_sources = {"nvd", "virustotal", "misp"}
    if source not in valid_sources:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid source '{source}'. Must be one of {sorted(valid_sources)}.",
        )

    redis_client = None
    try:
        import redis.asyncio as aioredis
        from app.config import get_settings
        settings = get_settings()
        redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    except Exception:
        raise HTTPException(status_code=503, detail="Redis unavailable — cannot invalidate cache.")

    await cache_invalidate(redis_client, source, query)
    await redis_client.aclose()

    logger.info(
        "Threat intel cache invalidated",
        source=source,
        query=query,
        by_user=current_user.id,
    )
    return {"status": "invalidated", "source": source, "query": query}

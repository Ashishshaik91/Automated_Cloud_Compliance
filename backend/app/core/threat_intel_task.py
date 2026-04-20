"""
Threat Intelligence Enrichment — Celery Task + Violations Enrichment.

Runs in two modes:
  1. Celery beat (scheduled every 6 hours): re-enriches all DSPM findings
     and open violations whose threat_intel_enriched_at is older than 24h
     or NULL.

  2. On-demand: called from the /api/v1/threat-intel/enrich endpoint for
     admin-triggered immediate enrichment.

Design:
  - Fail-open: any single finding/violation enrichment failure is logged
    and skipped; the rest continue.
  - Rate-conscious: NVD has 50 req/30s (no key) / 2000/day (with key).
    We batch by resource_type so CPE lookups are cached across findings of
    the same type (one NVD call → many findings).
  - Redis cache (24h TTL) prevents redundant external calls across runs.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from celery import shared_task
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AsyncSessionLocal

logger = structlog.get_logger(__name__)

# Re-enrich findings/violations older than this many hours
ENRICH_STALENESS_HOURS = 24


# ---------------------------------------------------------------------------
# DSPM findings enrichment
# ---------------------------------------------------------------------------

async def enrich_stale_dspm_findings(
    db: AsyncSession,
    redis_client: Any = None,
) -> dict[str, int]:
    """
    Re-enrich DSPM findings whose threat intel is stale or absent.

    Returns counts of {enriched, skipped, failed}.
    """
    from app.models.dspm import DSPMFinding
    from app.core.dspm_engine import enrich_with_threat_intel

    cutoff = datetime.now(timezone.utc) - timedelta(hours=ENRICH_STALENESS_HOURS)

    # Find findings that have never been enriched OR whose enrichment is stale
    result = await db.execute(
        select(DSPMFinding).where(
            (DSPMFinding.threat_intel_enriched_at == None)  # noqa: E711
            | (DSPMFinding.threat_intel_enriched_at < cutoff)
        )
    )
    findings = list(result.scalars().all())

    # Group by resource type for NVD cache efficiency (one CPE call per type)
    from app.integrations.nvd_client import query_nvd_cpe
    from app.integrations.threat_intel_cache import cache_get, cache_set

    nvd_cache: dict[str, list[dict]] = {}

    counts = {"enriched": 0, "skipped": 0, "failed": 0}
    for finding in findings:
        try:
            rtype = finding.data_store_type or "unknown"
            if rtype not in nvd_cache:
                cached = await cache_get(redis_client, "nvd", rtype) if redis_client else None
                if cached is not None:
                    nvd_cache[rtype] = cached
                else:
                    fetched = await query_nvd_cpe(rtype)
                    nvd_cache[rtype] = fetched
                    if redis_client:
                        await cache_set(redis_client, "nvd", rtype, fetched)

            # Inject pre-fetched CVE list to avoid redundant calls
            _original_query = None
            import app.integrations.nvd_client as _nvd_mod
            _original_query = _nvd_mod.query_nvd_cpe

            async def _cached_query(resource_type: str, **kwargs: Any) -> list[dict]:
                return nvd_cache.get(resource_type, [])

            _nvd_mod.query_nvd_cpe = _cached_query  # type: ignore[assignment]
            try:
                boost, boost_reason = await enrich_with_threat_intel(finding, redis_client)
            finally:
                if _original_query:
                    _nvd_mod.query_nvd_cpe = _original_query  # type: ignore[assignment]

            from app.models.dspm import risk_score_to_level
            base_score = finding.risk_score - finding.threat_intel_boost if finding.threat_intel_boost else finding.risk_score
            finding.risk_score = min(100.0, max(0.0, base_score + boost))
            finding.risk_level = risk_score_to_level(finding.risk_score)
            counts["enriched"] += 1

        except Exception as e:
            logger.warning(
                "DSPM finding enrichment failed",
                finding_id=finding.id,
                error=str(e),
            )
            counts["failed"] += 1

    await db.flush()
    logger.info("DSPM stale enrichment complete", **counts)
    return counts


# ---------------------------------------------------------------------------
# Violations enrichment (cve_ids, cvss_max columns from migration 0001)
# ---------------------------------------------------------------------------

async def enrich_open_violations(
    db: AsyncSession,
    redis_client: Any = None,
) -> dict[str, int]:
    """
    Enrich open Violation rows with NVD CVE data.

    Maps violation.resource_type → CPE → CVEs, writes cve_ids + cvss_max.
    Only processes violations where cve_ids is NULL (never enriched) or
    cvss_max is NULL (partial enrichment).

    Returns counts of {enriched, skipped, failed}.
    """
    from app.models.violations import Violation
    from app.integrations.nvd_client import query_nvd_cpe
    from app.integrations.misp_client import search_misp_events
    from app.integrations.threat_intel_cache import cache_get, cache_set

    result = await db.execute(
        select(Violation).where(
            Violation.status == "open",
            Violation.cve_ids == None,  # noqa: E711
        )
    )
    violations = list(result.scalars().all())

    counts = {"enriched": 0, "skipped": 0, "failed": 0}
    nvd_cache: dict[str, list[dict]] = {}

    for v in violations:
        try:
            rtype = v.resource_type or "unknown"

            # NVD CVE lookup (batched by resource type)
            if rtype not in nvd_cache:
                cached = await cache_get(redis_client, "nvd", rtype) if redis_client else None
                if cached is not None:
                    nvd_cache[rtype] = cached
                else:
                    fetched = await query_nvd_cpe(rtype)
                    nvd_cache[rtype] = fetched
                    if redis_client:
                        await cache_set(redis_client, "nvd", rtype, fetched)

            cves = nvd_cache[rtype]

            # MISP enrichment for resource IP/hostname (optional, fail-open)
            misp_events: list[dict] = []
            resource_ip = (v.details or {}).get("public_ip") or (v.details or {}).get("endpoint")
            if resource_ip:
                misp_cache_key = f"misp:{resource_ip}"
                misp_cached = await cache_get(redis_client, "misp", resource_ip) if redis_client else None
                if misp_cached is not None:
                    misp_events = misp_cached
                else:
                    misp_events = await search_misp_events(resource_ip)
                    if redis_client:
                        await cache_set(redis_client, "misp", resource_ip, misp_events)

            # Compute enriched fields
            cve_ids = [c["cve_id"] for c in cves]
            cvss_max = max((c["cvss_score"] for c in cves), default=None)

            # MISP severity bump — High (1) MISP events push cvss floor to 9.0
            if misp_events:
                high_misp = any(e.get("threat_level") == "1" for e in misp_events)
                if high_misp and (cvss_max is None or cvss_max < 9.0):
                    cvss_max = 9.0

            v.cve_ids = cve_ids
            v.cvss_max = cvss_max
            counts["enriched"] += 1

        except Exception as e:
            logger.warning(
                "Violation enrichment failed",
                violation_id=v.id,
                rule_id=v.rule_id,
                error=str(e),
            )
            counts["failed"] += 1

    await db.flush()
    logger.info("Violation enrichment complete", **counts)
    return counts


# ---------------------------------------------------------------------------
# Feed health check
# ---------------------------------------------------------------------------

async def check_feed_health(redis_client: Any = None) -> dict[str, Any]:
    """
    Probe each configured feed and report availability + last-updated.
    Used by GET /api/v1/threat-intel/health.
    """
    import httpx
    from app.config import get_settings
    settings = get_settings()

    health: dict[str, Any] = {}

    # NVD — unauthenticated probe against the meta endpoint
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"resultsPerPage": 1},
            )
            health["nvd"] = {
                "status": "ok" if r.status_code == 200 else "degraded",
                "http_status": r.status_code,
                "api_key_configured": bool(settings.nvd_api_key),
            }
    except Exception as e:
        health["nvd"] = {"status": "unreachable", "error": str(e)}

    # VirusTotal — check if key is configured (no free probe to avoid quota waste)
    vt_key = settings.virustotal_api_key.get_secret_value() if settings.virustotal_api_key else ""
    health["virustotal"] = {
        "status": "configured" if vt_key else "not_configured",
        "note": "Key present; no probe to conserve free-tier quota" if vt_key else
                "Set VIRUSTOTAL_API_KEY to enable IP reputation enrichment",
    }

    # MISP — probe if URL is configured
    if settings.misp_url:
        try:
            misp_key = settings.misp_api_key.get_secret_value() if settings.misp_api_key else ""
            # Use MISP_CA_CERT for self-signed/private-CA certs; system CA store otherwise
            tls_verify: str | bool = settings.misp_ca_cert if settings.misp_ca_cert else True
            async with httpx.AsyncClient(timeout=8.0, verify=tls_verify) as client:
                r = await client.get(
                    f"{settings.misp_url.rstrip('/')}/servers/getVersion",
                    headers={"Authorization": misp_key, "Accept": "application/json"},
                )
                health["misp"] = {
                    "status": "ok" if r.status_code == 200 else "degraded",
                    "http_status": r.status_code,
                    "url": settings.misp_url,
                }
        except Exception as e:
            health["misp"] = {
                "status": "unreachable",
                "url": settings.misp_url,
                "error": str(e),
            }
    else:
        health["misp"] = {
            "status": "not_configured",
            "note": "Set MISP_URL + MISP_API_KEY to enable MISP threat event enrichment",
        }

    # Redis cache stats
    if redis_client:
        try:
            nvd_keys = await redis_client.keys("ti:nvd:*")
            vt_keys  = await redis_client.keys("ti:virustotal:*")
            misp_keys = await redis_client.keys("ti:misp:*")
            health["cache"] = {
                "status": "connected",
                "nvd_cached_entries": len(nvd_keys),
                "vt_cached_entries":  len(vt_keys),
                "misp_cached_entries": len(misp_keys),
            }
        except Exception as e:
            health["cache"] = {"status": "error", "error": str(e)}
    else:
        health["cache"] = {"status": "unavailable"}

    return health


# ---------------------------------------------------------------------------
# Celery Tasks
# ---------------------------------------------------------------------------

async def _run_scheduled_enrichment_async() -> dict[str, Any]:
    redis_client = None
    try:
        import redis.asyncio as aioredis
        from app.config import get_settings
        settings = get_settings()
        redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    except Exception:
        logger.warning("Redis unavailable for scheduled enrichment")

    results: dict[str, Any] = {}
    async with AsyncSessionLocal() as db:
        async with db.begin():
            results["dspm"] = await enrich_stale_dspm_findings(db, redis_client)
            results["violations"] = await enrich_open_violations(db, redis_client)

    if redis_client:
        try:
            await redis_client.aclose()
        except Exception:
            pass
    return results


@shared_task(name="tasks.run_scheduled_enrichment")
def run_scheduled_enrichment() -> dict[str, Any]:
    """
    Celery beat task. Runs background threat intel enrichment.
    """
    logger.info("Starting scheduled threat intel enrichment")
    import sys
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    return asyncio.run(_run_scheduled_enrichment_async())

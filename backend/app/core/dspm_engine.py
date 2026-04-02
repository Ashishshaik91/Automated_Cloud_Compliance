"""
DSPM Engine — sensitive data discovery, classification, and risk scoring.
Feature 4: Enriched with NVD CVE and VirusTotal threat intel.

Risk score formula (revised):
  base_score (0–80)     = sensitivity weight × encryption_factor × public_multiplier
  threat_intel_boost (0–20):
    +10 per critical CVE (CVSS ≥ 9.0), capped at +20 from CVEs
    +20 if VT reputation > 0.5
    (takes whichever is higher of CVE-boost or VT-boost)
  final_score = min(100, max(0, base_score + threat_intel_boost))

Enrichment is async, cached (Redis TTL 24h), and fail-open:
  enrichment failure logs a warning and leaves threat_intel_enriched_at = None.
  The scan proceeds with base_score intact.

Audit event emitted on enrichment (picked up by existing audit chain):
  event: risk_score_enriched
  fields: finding_id, before_score, threat_intel_boost, boost_reason, after_score
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dspm import DSPMFinding, risk_score_to_level

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Sensitivity weight map (base_score range: 0–80)
# ---------------------------------------------------------------------------
_SENSITIVITY_WEIGHT = {"critical": 80, "high": 56, "medium": 32, "low": 12}
_ENCRYPTION_FACTOR  = {"encrypted": 1.0, "partial": 1.4, "unencrypted": 2.0}
_PUBLIC_MULTIPLIER  = 1.6


def _compute_base_score(sensitivity: str, public_access: bool, encryption: str) -> float:
    """Compute the internal base risk score (0.0–80.0)."""
    base  = _SENSITIVITY_WEIGHT.get(sensitivity, 12)
    score = base * _ENCRYPTION_FACTOR.get(encryption, 1.0)
    if public_access:
        score *= _PUBLIC_MULTIPLIER
    return min(round(score, 1), 80.0)


def _compute_threat_intel_boost(
    cve_list: list[dict[str, Any]],
    vt_reputation: float | None,
) -> tuple[float, dict[str, Any]]:
    """
    Compute the threat intel boost (0.0–20.0) and return it with a boost_reason dict.

    CVE boost:  +10 per critical CVE (CVSS ≥ 9.0), capped at +20 total.
    VT boost:   +20 if vt_reputation > 0.5.
    Final boost = max(cve_boost, vt_boost), capped at 20.
    """
    critical_cves = [c for c in cve_list if c.get("cvss_score", 0) >= 9.0]
    cve_boost     = min(len(critical_cves) * 10, 20)

    vt_boost = 0.0
    if vt_reputation is not None and vt_reputation > 0.5:
        vt_boost = 20.0

    final_boost = max(cve_boost, vt_boost)
    boost_reason = {
        "cve_ids":       [c["cve_id"] for c in cve_list],
        "cvss_max":      max((c["cvss_score"] for c in cve_list), default=0.0),
        "vt_reputation": vt_reputation,
        "cve_boost":     cve_boost,
        "vt_boost":      vt_boost,
    }
    return final_boost, boost_reason


# ---------------------------------------------------------------------------
# Simulated data store inventory
# ---------------------------------------------------------------------------
_DATA_STORES: list[dict[str, Any]] = [
    # ── AWS S3 ──────────────────────────────────────────────────────────
    {
        "data_store_id":   "pii-production-lake",
        "data_store_name": "S3 PII Production Lake",
        "data_store_type": "s3",
        "cloud_provider":  "aws",
        "account_id":      "123456789012",
        "region":          "us-east-1",
        "classifications": "PII,PCI",
        "sensitivity":     "critical",
        "public_access":   True,
        "encryption_status": "partial",
        "record_count":    4_200_000,
        "owner":           "data-engineering@corp.internal",
    },
    {
        "data_store_id":   "analytics-public-exports",
        "data_store_name": "S3 Analytics Public Exports",
        "data_store_type": "s3",
        "cloud_provider":  "aws",
        "account_id":      "123456789012",
        "region":          "us-west-2",
        "classifications": "CONFIDENTIAL",
        "sensitivity":     "high",
        "public_access":   True,
        "encryption_status": "unencrypted",
        "record_count":    890_000,
        "owner":           "analytics-team@corp.internal",
    },
    {
        "data_store_id":   "s3-audit-logs-archive",
        "data_store_name": "S3 Audit Logs Archive",
        "data_store_type": "s3",
        "cloud_provider":  "aws",
        "account_id":      "123456789012",
        "region":          "us-east-1",
        "classifications": "CONFIDENTIAL",
        "sensitivity":     "medium",
        "public_access":   False,
        "encryption_status": "encrypted",
        "record_count":    12_000_000,
        "owner":           "security-team@corp.internal",
    },
    # ── AWS RDS ─────────────────────────────────────────────────────────
    {
        "data_store_id":   "prod-db-mysql",
        "data_store_name": "RDS prod-db-mysql",
        "data_store_type": "rds",
        "cloud_provider":  "aws",
        "account_id":      "123456789012",
        "region":          "us-east-1",
        "classifications": "PHI,HIPAA",
        "sensitivity":     "critical",
        "public_access":   True,
        "encryption_status": "encrypted",
        "record_count":    1_100_000,
        "owner":           "backend-team@corp.internal",
    },
    {
        "data_store_id":   "rds-reporting-replica",
        "data_store_name": "RDS Reporting Replica",
        "data_store_type": "rds",
        "cloud_provider":  "aws",
        "account_id":      "123456789012",
        "region":          "eu-west-1",
        "classifications": "CONFIDENTIAL",
        "sensitivity":     "high",
        "public_access":   False,
        "encryption_status": "encrypted",
        "record_count":    560_000,
        "owner":           "reporting-team@corp.internal",
    },
    # ── Azure Blob ───────────────────────────────────────────────────────
    {
        "data_store_id":   "stgaccountprodeurwest",
        "data_store_name": "Azure Storage stgaccountprodeurwest",
        "data_store_type": "blob",
        "cloud_provider":  "azure",
        "account_id":      "sub-0001-prod",
        "region":          "westeurope",
        "classifications": "PII,CONFIDENTIAL",
        "sensitivity":     "high",
        "public_access":   False,
        "encryption_status": "partial",
        "record_count":    340_000,
        "owner":           "platform-team@corp.internal",
    },
    {
        "data_store_id":   "az-backup-store-01",
        "data_store_name": "Azure Backup Store 01",
        "data_store_type": "blob",
        "cloud_provider":  "azure",
        "account_id":      "sub-0001-prod",
        "region":          "northeurope",
        "classifications": "CONFIDENTIAL",
        "sensitivity":     "medium",
        "public_access":   False,
        "encryption_status": "encrypted",
        "record_count":    9_800_000,
        "owner":           "infra-team@corp.internal",
    },
    # ── GCP GCS ─────────────────────────────────────────────────────────
    {
        "data_store_id":   "gcs-ml-training-data",
        "data_store_name": "GCS ML Training Dataset",
        "data_store_type": "gcs",
        "cloud_provider":  "gcp",
        "account_id":      "proj-frontend-prod",
        "region":          "us-central1",
        "classifications": "PII,CONFIDENTIAL",
        "sensitivity":     "high",
        "public_access":   True,
        "encryption_status": "encrypted",
        "record_count":    7_500_000,
        "owner":           "ml-team@corp.internal",
    },
    {
        "data_store_id":   "gcs-data-transfer-zone",
        "data_store_name": "GCS Transient Data Transfer Zone",
        "data_store_type": "gcs",
        "cloud_provider":  "gcp",
        "account_id":      "proj-frontend-prod",
        "region":          "europe-west1",
        "classifications": "UNKNOWN",
        "sensitivity":     "low",
        "public_access":   False,
        "encryption_status": "encrypted",
        "record_count":    None,
        "owner":           None,
    },
    # ── GCP BigQuery ─────────────────────────────────────────────────────
    {
        "data_store_id":   "bq-customer-analytics",
        "data_store_name": "BigQuery Customer Analytics",
        "data_store_type": "bigquery",
        "cloud_provider":  "gcp",
        "account_id":      "proj-analytics",
        "region":          "us",
        "classifications": "PII,PCI",
        "sensitivity":     "critical",
        "public_access":   False,
        "encryption_status": "encrypted",
        "record_count":    22_000_000,
        "owner":           "analytics-team@corp.internal",
    },
]


def _make_dspm_urn(cloud_provider: str, account_id: str, store_type: str, store_id: str) -> str:
    """Mirrors the URN format used in violations_engine._make_urn."""
    return f"{cloud_provider}://{account_id}/{store_type}/{store_id.lower()}"


# ---------------------------------------------------------------------------
# Threat intel enrichment (Feature 4)
# ---------------------------------------------------------------------------

async def enrich_with_threat_intel(
    finding: DSPMFinding,
    redis_client: Any = None,
) -> tuple[float, dict[str, Any]]:
    """
    Query NVD (CPE-based) and VirusTotal to compute a threat intel boost.

    Returns (boost, boost_reason). On any failure, returns (0.0, {}).
    Updates finding fields in-place; caller must flush/commit the session.
    """
    from app.integrations.nvd_client import query_nvd_cpe
    from app.integrations.virustotal_client import get_ip_reputation
    from app.integrations.threat_intel_cache import cache_get, cache_set

    try:
        # NVD CVE lookup (cached)
        nvd_cache_key = f"{finding.data_store_type}:{finding.cloud_provider}"
        cve_list = await cache_get(redis_client, "nvd", nvd_cache_key) if redis_client else None
        if cve_list is None:
            cve_list = await query_nvd_cpe(finding.data_store_type)
            if redis_client:
                await cache_set(redis_client, "nvd", nvd_cache_key, cve_list)

        # VT IP reputation — only if the store is publicly accessible
        vt_reputation = None
        if finding.public_access:
            vt_reputation = await get_ip_reputation("0.0.0.0", redis_client=redis_client)  # placeholder IP

        boost, boost_reason = _compute_threat_intel_boost(cve_list, vt_reputation)

        # Update finding fields
        finding.cve_ids                  = cve_list
        finding.cvss_max                 = boost_reason["cvss_max"]
        finding.vt_reputation            = vt_reputation
        finding.threat_intel_boost       = boost
        finding.threat_intel_enriched_at = datetime.now(timezone.utc)

        return boost, boost_reason

    except Exception as e:
        logger.warning(
            "Threat intel enrichment failed; using base_score only",
            finding_id=finding.id,
            error=str(e),
        )
        return 0.0, {}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

async def run_dspm_engine(
    db: AsyncSession,
    redis_client: Any = None,
    enrich: bool = True,
) -> int:
    """
    Upsert DSPMFinding rows from the simulated inventory.
    Optionally enriches with threat intel (enrich=True by default).
    Returns the number of newly created rows.
    """
    created = 0
    for store in _DATA_STORES:
        urn = _make_dspm_urn(
            store["cloud_provider"], store["account_id"],
            store["data_store_type"], store["data_store_id"]
        )

        base_score = _compute_base_score(
            store["sensitivity"], store["public_access"], store["encryption_status"]
        )

        existing = (await db.execute(
            select(DSPMFinding).where(DSPMFinding.data_store_urn == urn)
        )).scalar_one_or_none()

        if existing:
            # Recalculate base score on update
            if enrich:
                boost, boost_reason = await enrich_with_threat_intel(existing, redis_client)
                final_score = min(100.0, max(0.0, base_score + boost))
                before_score = existing.risk_score
                existing.risk_score             = final_score
                existing.risk_level             = risk_score_to_level(final_score)
                existing.last_scanned           = datetime.now(timezone.utc)
                # Emit structured audit log for score enrichment
                logger.info(
                    "risk_score_enriched",
                    finding_id=existing.id,
                    before_score=before_score,
                    threat_intel_boost=boost,
                    boost_reason=boost_reason,
                    after_score=final_score,
                    enriched_at=datetime.now(timezone.utc).isoformat(),
                )
            else:
                await db.execute(
                    update(DSPMFinding)
                    .where(DSPMFinding.data_store_urn == urn)
                    .values(
                        risk_score=base_score,
                        risk_level=risk_score_to_level(base_score),
                        last_scanned=datetime.now(timezone.utc),
                    )
                )
            continue

        # Create new finding
        new_finding = DSPMFinding(
            data_store_urn     = urn,
            data_store_id      = store["data_store_id"],
            data_store_name    = store["data_store_name"],
            data_store_type    = store["data_store_type"],
            cloud_provider     = store["cloud_provider"],
            region             = store.get("region"),
            account_id         = store.get("account_id"),
            classifications    = store["classifications"],
            sensitivity        = store["sensitivity"],
            public_access      = store["public_access"],
            encryption_status  = store["encryption_status"],
            record_count       = store.get("record_count"),
            owner              = store.get("owner"),
            risk_score         = base_score,
            risk_level         = risk_score_to_level(base_score),
        )
        db.add(new_finding)
        await db.flush()   # get ID for logging

        if enrich:
            boost, boost_reason = await enrich_with_threat_intel(new_finding, redis_client)
            final_score = min(100.0, max(0.0, base_score + boost))
            new_finding.risk_score = final_score
            new_finding.risk_level = risk_score_to_level(final_score)
            logger.info(
                "risk_score_enriched",
                finding_id=new_finding.id,
                before_score=base_score,
                threat_intel_boost=boost,
                boost_reason=boost_reason,
                after_score=final_score,
                enriched_at=datetime.now(timezone.utc).isoformat(),
            )

        created += 1

    await db.flush()
    logger.info("DSPM engine run complete", new=created, total=len(_DATA_STORES))
    return created

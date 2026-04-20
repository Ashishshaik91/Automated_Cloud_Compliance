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
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dspm import DSPMFinding, risk_score_to_level
from app.models.compliance import CloudAccount
from app.connectors.aws_connector import AWSConnector
from app.connectors.gcp_connector import GCPConnector

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
# Simulated data store inventory removed in favor of live queries
# ---------------------------------------------------------------------------


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
    Query NVD (CPE-based), VirusTotal, and MISP to compute a threat intel boost.

    Returns (boost, boost_reason). On any failure, returns (0.0, {}).
    Updates finding fields in-place; caller must flush/commit the session.
    """
    from app.integrations.nvd_client import query_nvd_cpe
    from app.integrations.virustotal_client import get_ip_reputation
    from app.integrations.misp_client import search_misp_events
    from app.integrations.threat_intel_cache import cache_get, cache_set

    try:
        # ── NVD CVE lookup (cached by resource type) ─────────────────────
        nvd_cache_key = f"{finding.data_store_type}:{finding.cloud_provider}"
        cve_list = await cache_get(redis_client, "nvd", nvd_cache_key) if redis_client else None
        if cve_list is None:
            cve_list = await query_nvd_cpe(finding.data_store_type)
            if redis_client:
                await cache_set(redis_client, "nvd", nvd_cache_key, cve_list)

        # ── VirusTotal IP reputation ──────────────────────────────────────
        # Only query if the store is publicly accessible AND we have a real endpoint.
        # data_store_id is the bucket/account name — use it as the VT "domain" query
        # for S3/GCS/blob hostnames; fall back to None (skips VT).
        vt_reputation = None
        if finding.public_access:
            # Build a plausible public hostname to query (best-effort)
            endpoint = _build_public_endpoint(finding.data_store_type, finding.data_store_id)
            if endpoint:
                vt_cache_key = f"vt:{endpoint}"
                vt_reputation = await cache_get(redis_client, "virustotal", endpoint) if redis_client else None
                if vt_reputation is None:
                    vt_reputation = await get_ip_reputation(endpoint, redis_client=redis_client)
                    if vt_reputation is not None and redis_client:
                        await cache_set(redis_client, "virustotal", endpoint, vt_reputation)

        # ── MISP threat event lookup ──────────────────────────────────────
        misp_events: list[dict[str, Any]] = []
        if finding.public_access and finding.data_store_id:
            misp_cache_key = finding.data_store_id
            misp_events = await cache_get(redis_client, "misp", misp_cache_key) if redis_client else None
            if misp_events is None:
                misp_events = await search_misp_events(finding.data_store_id)
                if redis_client:
                    await cache_set(redis_client, "misp", misp_cache_key, misp_events)

        # ── Compute composite boost ───────────────────────────────────────
        boost, boost_reason = _compute_threat_intel_boost(cve_list, vt_reputation)

        # MISP boost: High-severity MISP event (threat_level_id=1) → +15, Medium (2) → +8
        misp_boost = 0.0
        if misp_events:
            levels = [int(e.get("threat_level", 4)) for e in misp_events]
            if 1 in levels:
                misp_boost = 15.0
            elif 2 in levels:
                misp_boost = 8.0
        boost = min(20.0, max(boost, misp_boost))  # cap at 20 total
        boost_reason["misp_events"] = len(misp_events)
        boost_reason["misp_boost"]  = misp_boost

        # ── Update finding in-place ───────────────────────────────────────
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


def _build_public_endpoint(store_type: str, store_id: str) -> str | None:
    """
    Build a plausible public hostname for VT reputation lookup.
    Returns None for private store types where VT is not meaningful.
    """
    store_type = (store_type or "").lower()
    if store_type in ("s3", "gcs", "blob", "bigquery"):
        return store_id[:253]  # max domain label length
    return None

# ---------------------------------------------------------------------------
# Classification helper
# ---------------------------------------------------------------------------

def _classify_by_name(
    name: str,
    default_cls: str = "CONFIDENTIAL",
    default_sens: str = "medium",
) -> tuple[str, str]:
    """
    Infer data classification and sensitivity level from a store name/ID.
    Returns (classifications_csv, sensitivity_level).
    """
    n = name.lower()
    if "pii" in n or "pci" in n or "payment" in n or "card" in n:
        return "PII,PCI", "critical"
    if "phi" in n or "medical" in n or "hipaa" in n or "health" in n or "patient" in n:
        return "PHI,HIPAA", "high"
    if "gdpr" in n or "eu-" in n or "eu_" in n or "privacy" in n:
        return "GDPR,PII", "high"
    if "prod" in n or "production" in n or "live" in n:
        return "PII,PCI", "critical"
    if "exposed" in n or "backup" in n or "legacy" in n or "archive" in n:
        return "PII,PCI", "critical"
    if "test" in n or "dev" in n or "staging" in n or "synthetic" in n or "demo" in n:
        return "UNKNOWN", "low"
    return default_cls, default_sens


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

async def run_dspm_engine(
    db: AsyncSession,
    redis_client: Any = None,
    enrich: bool = True,
) -> int:
    """
    Scan all active cloud accounts (AWS + GCP) for sensitive data stores.
    Classifies by name/type keywords, computes risk scores, and optionally
    enriches with threat intel. Returns count of newly created findings.
    """
    await db.execute(delete(DSPMFinding))
    await db.flush()

    created = 0
    accounts = (await db.execute(select(CloudAccount).where(CloudAccount.is_active == True))).scalars().all()

    for account in accounts:
        live_stores: list[dict] = []

        try:
            # ── AWS: S3 + RDS ────────────────────────────────────────────
            if account.provider == "aws":
                conn = AWSConnector(account)
                buckets = conn._get_s3_buckets()
                rds_instances = conn._get_rds_instances()

                for b in buckets:
                    name = b["resource_id"]
                    cls, sens = _classify_by_name(name)
                    encrypted = "encrypted" if b.get("encryption_enabled", False) else "unencrypted"
                    live_stores.append({
                        "data_store_id":   name,
                        "data_store_name": f"S3 {name}",
                        "data_store_type": "s3",
                        "cloud_provider":  "aws",
                        "account_id":      account.account_id,
                        "region":          account.region or "us-east-1",
                        "classifications": cls,
                        "sensitivity":     sens,
                        "public_access":   not b.get("public_access_blocked", True),
                        "encryption_status": encrypted,
                    })

                for r in rds_instances:
                    name = r["resource_id"]
                    cls, sens = _classify_by_name(name, default_cls="PHI,HIPAA", default_sens="high")
                    encrypted = "encrypted" if r.get("encrypted", False) else "unencrypted"
                    live_stores.append({
                        "data_store_id":   name,
                        "data_store_name": f"RDS {name}",
                        "data_store_type": "rds",
                        "cloud_provider":  "aws",
                        "account_id":      account.account_id,
                        "region":          account.region or "us-east-1",
                        "classifications": cls,
                        "sensitivity":     sens,
                        "public_access":   r.get("publicly_accessible", False),
                        "encryption_status": encrypted,
                    })

            # ── GCP: GCS + Cloud SQL ─────────────────────────────────────
            elif account.provider == "gcp":
                conn = GCPConnector(account)
                gcs_buckets   = conn._get_gcs_buckets()
                cloud_sql     = conn._get_cloud_sql_instances()

                for b in gcs_buckets:
                    name = b["resource_id"]
                    cls, sens = _classify_by_name(name)
                    # GCS: uniform_bucket_level_access = True means no public ACLs
                    public_blocked = b.get("uniform_bucket_level_access", False) or b.get("public_access_blocked", False)
                    live_stores.append({
                        "data_store_id":   name,
                        "data_store_name": f"GCS {name}",
                        "data_store_type": "gcs",
                        "cloud_provider":  "gcp",
                        "account_id":      account.account_id,
                        "region":          b.get("location") or account.region or "us-central1",
                        "classifications": cls,
                        "sensitivity":     sens,
                        "public_access":   not public_blocked,
                        "encryption_status": "encrypted",  # GCS always encrypts at rest
                    })

                for sql in cloud_sql:
                    name = sql["resource_id"]
                    cls, sens = _classify_by_name(name, default_cls="PHI,HIPAA", default_sens="high")
                    # If authorized_networks contains 0.0.0.0/0, it's publicly accessible
                    auth_nets = sql.get("authorized_networks", [])
                    public = any(n.get("value") == "0.0.0.0/0" for n in auth_nets if isinstance(n, dict))
                    live_stores.append({
                        "data_store_id":   name,
                        "data_store_name": f"CloudSQL {name}",
                        "data_store_type": "cloud_sql",
                        "cloud_provider":  "gcp",
                        "account_id":      account.account_id,
                        "region":          account.region or "us-central1",
                        "classifications": cls,
                        "sensitivity":     sens,
                        "public_access":   public,
                        "encryption_status": "encrypted",  # Cloud SQL encrypts at rest
                    })

            else:
                # Azure or other — skip for now
                continue

        except Exception as e:
            logger.error(f"Failed to process DSPM for account {account.account_id}", error=str(e))
            continue

        # ── Persist findings ──────────────────────────────────────────────────
        for store in live_stores:
            urn = _make_dspm_urn(
                store["cloud_provider"], store["account_id"],
                store["data_store_type"], store["data_store_id"]
            )
            base_score = _compute_base_score(
                store["sensitivity"], store["public_access"], store["encryption_status"]
            )
            new_finding = DSPMFinding(
                data_store_urn    = urn,
                data_store_id     = store["data_store_id"],
                data_store_name   = store["data_store_name"],
                data_store_type   = store["data_store_type"],
                cloud_provider    = store["cloud_provider"],
                region            = store.get("region"),
                account_id        = store.get("account_id"),
                cloud_account_id  = account.id,
                classifications   = store["classifications"],
                sensitivity       = store["sensitivity"],
                public_access     = store["public_access"],
                encryption_status = store["encryption_status"],
                risk_score        = base_score,
                risk_level        = risk_score_to_level(base_score),
            )
            db.add(new_finding)
            await db.flush()

            if enrich:
                boost, _ = await enrich_with_threat_intel(new_finding, redis_client)
                final_score = min(100.0, max(0.0, base_score + boost))
                new_finding.risk_score = final_score
                new_finding.risk_level = risk_score_to_level(final_score)

            created += 1

    await db.flush()
    logger.info("DSPM engine run complete", new=created)
    return created

"""
DSPM Engine — sensitive data discovery, classification, and risk scoring.

Simulates scanning cloud data stores, classifies their contents, computes
a 0-100 risk_score, and maps that to a risk_level.  Run is idempotent
(upserts by data_store_urn) so periodic refreshes update existing rows.
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
# Sensitivity weight map  (higher = more sensitive)
# ---------------------------------------------------------------------------
_SENSITIVITY_WEIGHT = {"critical": 100, "high": 70, "medium": 40, "low": 15}
_ENCRYPTION_FACTOR  = {"encrypted": 1.0, "partial": 1.4, "unencrypted": 2.0}
_PUBLIC_MULTIPLIER  = 2.0


def _compute_risk(sensitivity: str, public_access: bool, encryption: str) -> float:
    base = _SENSITIVITY_WEIGHT.get(sensitivity, 15)
    score = base * _ENCRYPTION_FACTOR.get(encryption, 1.0)
    if public_access:
        score *= _PUBLIC_MULTIPLIER
    return min(round(score, 1), 100.0)


# ---------------------------------------------------------------------------
# Simulated data store inventory
# ---------------------------------------------------------------------------
# resource_id segments are kept simple so the correlator can match them against
# Violation.resource_id (same casing, no ARN prefix).

_DATA_STORES: list[dict[str, Any]] = [
    # ── AWS S3 ──────────────────────────────────────────────────────────
    {
        "data_store_id": "pii-production-lake",
        "data_store_name": "S3 PII Production Lake",
        "data_store_type": "s3",
        "cloud_provider": "aws",
        "account_id": "123456789012",
        "region": "us-east-1",
        "classifications": "PII,PCI",
        "sensitivity": "critical",
        "public_access": True,          # matches AWS-S3-001 violation
        "encryption_status": "partial",
        "record_count": 4_200_000,
        "owner": "data-engineering@corp.internal",
    },
    {
        "data_store_id": "analytics-public-exports",
        "data_store_name": "S3 Analytics Public Exports",
        "data_store_type": "s3",
        "cloud_provider": "aws",
        "account_id": "123456789012",
        "region": "us-west-2",
        "classifications": "CONFIDENTIAL",
        "sensitivity": "high",
        "public_access": True,          # matches AWS-S3-001 violation
        "encryption_status": "unencrypted",
        "record_count": 890_000,
        "owner": "analytics-team@corp.internal",
    },
    {
        "data_store_id": "s3-audit-logs-archive",
        "data_store_name": "S3 Audit Logs Archive",
        "data_store_type": "s3",
        "cloud_provider": "aws",
        "account_id": "123456789012",
        "region": "us-east-1",
        "classifications": "CONFIDENTIAL",
        "sensitivity": "medium",
        "public_access": False,
        "encryption_status": "encrypted",
        "record_count": 12_000_000,
        "owner": "security-team@corp.internal",
    },
    # ── AWS RDS ─────────────────────────────────────────────────────────
    {
        "data_store_id": "prod-db-mysql",
        "data_store_name": "RDS prod-db-mysql",
        "data_store_type": "rds",
        "cloud_provider": "aws",
        "account_id": "123456789012",
        "region": "us-east-1",
        "classifications": "PHI,HIPAA",
        "sensitivity": "critical",
        "public_access": True,          # matches AWS-RDS-001 violation
        "encryption_status": "encrypted",
        "record_count": 1_100_000,
        "owner": "backend-team@corp.internal",
    },
    {
        "data_store_id": "rds-reporting-replica",
        "data_store_name": "RDS Reporting Replica",
        "data_store_type": "rds",
        "cloud_provider": "aws",
        "account_id": "123456789012",
        "region": "eu-west-1",
        "classifications": "CONFIDENTIAL",
        "sensitivity": "high",
        "public_access": False,
        "encryption_status": "encrypted",
        "record_count": 560_000,
        "owner": "reporting-team@corp.internal",
    },
    # ── Azure Blob ───────────────────────────────────────────────────────
    {
        "data_store_id": "stgaccountprodeurwest",
        "data_store_name": "Azure Storage stgaccountprodeurwest",
        "data_store_type": "blob",
        "cloud_provider": "azure",
        "account_id": "sub-0001-prod",
        "region": "westeurope",
        "classifications": "PII,CONFIDENTIAL",
        "sensitivity": "high",
        "public_access": False,
        "encryption_status": "partial",  # HTTP allowed (AZ-ST-001)
        "record_count": 340_000,
        "owner": "platform-team@corp.internal",
    },
    {
        "data_store_id": "az-backup-store-01",
        "data_store_name": "Azure Backup Store 01",
        "data_store_type": "blob",
        "cloud_provider": "azure",
        "account_id": "sub-0001-prod",
        "region": "northeurope",
        "classifications": "CONFIDENTIAL",
        "sensitivity": "medium",
        "public_access": False,
        "encryption_status": "encrypted",
        "record_count": 9_800_000,
        "owner": "infra-team@corp.internal",
    },
    # ── GCP GCS ─────────────────────────────────────────────────────────
    {
        "data_store_id": "gcs-ml-training-data",
        "data_store_name": "GCS ML Training Dataset",
        "data_store_type": "gcs",
        "cloud_provider": "gcp",
        "account_id": "proj-frontend-prod",
        "region": "us-central1",
        "classifications": "PII,CONFIDENTIAL",
        "sensitivity": "high",
        "public_access": True,          # matches GCP-GCS-001 violation
        "encryption_status": "encrypted",
        "record_count": 7_500_000,
        "owner": "ml-team@corp.internal",
    },
    {
        "data_store_id": "gcs-data-transfer-zone",
        "data_store_name": "GCS Transient Data Transfer Zone",
        "data_store_type": "gcs",
        "cloud_provider": "gcp",
        "account_id": "proj-frontend-prod",
        "region": "europe-west1",
        "classifications": "UNKNOWN",
        "sensitivity": "low",
        "public_access": False,
        "encryption_status": "encrypted",
        "record_count": None,
        "owner": None,
    },
    # ── GCP BigQuery ─────────────────────────────────────────────────────
    {
        "data_store_id": "bq-customer-analytics",
        "data_store_name": "BigQuery Customer Analytics",
        "data_store_type": "bigquery",
        "cloud_provider": "gcp",
        "account_id": "proj-analytics",
        "region": "us",
        "classifications": "PII,PCI",
        "sensitivity": "critical",
        "public_access": False,
        "encryption_status": "encrypted",
        "record_count": 22_000_000,
        "owner": "analytics-team@corp.internal",
    },
]


def _make_dspm_urn(cloud_provider: str, account_id: str, store_type: str, store_id: str) -> str:
    """Mirrors the URN format used in violations_engine._make_urn."""
    return f"{cloud_provider}://{account_id}/{store_type}/{store_id.lower()}"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

async def run_dspm_engine(db: AsyncSession) -> int:
    """
    Upsert DSPMFinding rows from the simulated inventory.
    Returns the number of newly created rows.
    """
    created = 0
    for store in _DATA_STORES:
        urn = _make_dspm_urn(
            store["cloud_provider"], store["account_id"],
            store["data_store_type"], store["data_store_id"]
        )

        risk_score = _compute_risk(
            store["sensitivity"], store["public_access"], store["encryption_status"]
        )
        risk_level = risk_score_to_level(risk_score)

        existing = (await db.execute(
            select(DSPMFinding).where(DSPMFinding.data_store_urn == urn)
        )).scalar_one_or_none()

        if existing:
            await db.execute(
                update(DSPMFinding)
                .where(DSPMFinding.data_store_urn == urn)
                .values(
                    risk_score=risk_score,
                    risk_level=risk_level,
                    last_scanned=datetime.now(timezone.utc),
                )
            )
            continue

        db.add(DSPMFinding(
            data_store_urn=urn,
            data_store_id=store["data_store_id"],
            data_store_name=store["data_store_name"],
            data_store_type=store["data_store_type"],
            cloud_provider=store["cloud_provider"],
            region=store.get("region"),
            account_id=store.get("account_id"),
            classifications=store["classifications"],
            sensitivity=store["sensitivity"],
            public_access=store["public_access"],
            encryption_status=store["encryption_status"],
            record_count=store.get("record_count"),
            owner=store.get("owner"),
            risk_score=risk_score,
            risk_level=risk_level,
        ))
        created += 1

    await db.flush()
    logger.info("DSPM engine run complete", new=created, total=len(_DATA_STORES))
    return created

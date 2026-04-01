"""
DSPM API — sensitive data discovery, classification, and access/risk analysis.
"""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AsyncSessionLocal
from app.models.dspm import DSPMFinding, DSPMCorrelation
from app.models.violations import Violation
from app.core.dspm_engine import run_dspm_engine
from app.core.correlator import run_correlator
from app.auth.dependencies import get_current_user

router = APIRouter()


async def get_db():
    async with AsyncSessionLocal() as db:
        yield db


# ── DSPM Findings ────────────────────────────────────────────────────────────

@router.get("/findings")
async def list_dspm_findings(
    classification: Optional[str] = Query(None, description="e.g. PII, PCI, PHI"),
    sensitivity:    Optional[str] = Query(None, description="critical/high/medium/low"),
    provider:       Optional[str] = Query(None, description="aws/azure/gcp"),
    public_only:    bool          = Query(False),
    limit:          int           = Query(200, le=500),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    stmt = select(DSPMFinding)
    if classification:
        stmt = stmt.where(DSPMFinding.classifications.contains(classification.upper()))
    if sensitivity:
        stmt = stmt.where(DSPMFinding.sensitivity == sensitivity.lower())
    if provider:
        stmt = stmt.where(DSPMFinding.cloud_provider == provider.lower())
    if public_only:
        stmt = stmt.where(DSPMFinding.public_access == True)  # noqa: E712

    stmt = stmt.order_by(DSPMFinding.risk_score.desc()).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()

    return [
        {
            "id":               f.id,
            "data_store_urn":   f.data_store_urn,
            "data_store_id":    f.data_store_id,
            "data_store_name":  f.data_store_name,
            "data_store_type":  f.data_store_type,
            "cloud_provider":   f.cloud_provider,
            "region":           f.region,
            "account_id":       f.account_id,
            "classifications":  f.classifications.split(",") if f.classifications else [],
            "sensitivity":      f.sensitivity,
            "public_access":    f.public_access,
            "encryption_status":f.encryption_status,
            "record_count":     f.record_count,
            "owner":            f.owner,
            "risk_score":       f.risk_score,
            "risk_level":       f.risk_level,
            "last_scanned":     f.last_scanned.isoformat(),
        }
        for f in rows
    ]


# ── DSPM Summary ─────────────────────────────────────────────────────────────

@router.get("/summary")
async def dspm_summary(
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    findings = (await db.execute(select(DSPMFinding))).scalars().all()

    total         = len(findings)
    at_risk       = sum(1 for f in findings if f.risk_level in ("critical", "high"))
    public_stores = sum(1 for f in findings if f.public_access)
    unencrypted   = sum(1 for f in findings if f.encryption_status == "unencrypted")
    avg_risk_score = round(sum(f.risk_score for f in findings) / total, 1) if total else 0

    # Classification breakdown
    class_counts: dict[str, int] = {}
    for f in findings:
        for tag in f.classifications.split(","):
            tag = tag.strip()
            if tag:
                class_counts[tag] = class_counts.get(tag, 0) + 1

    # Risk level breakdown
    risk_breakdown: dict[str, int] = {}
    for f in findings:
        risk_breakdown[f.risk_level] = risk_breakdown.get(f.risk_level, 0) + 1

    # Provider breakdown
    provider_counts: dict[str, int] = {}
    for f in findings:
        provider_counts[f.cloud_provider] = provider_counts.get(f.cloud_provider, 0) + 1

    return {
        "total_stores":          total,
        "at_risk":               at_risk,
        "public_stores":         public_stores,
        "unencrypted_stores":    unencrypted,
        "avg_risk_score":        avg_risk_score,
        "classifications":       class_counts,
        "risk_breakdown":        risk_breakdown,
        "by_provider":           provider_counts,
    }


# ── Correlations ─────────────────────────────────────────────────────────────

@router.get("/correlations")
async def list_correlations(
    combined_risk: Optional[str] = Query(None),
    limit:         int           = Query(100, le=300),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    stmt = select(DSPMCorrelation)
    if combined_risk:
        stmt = stmt.where(DSPMCorrelation.combined_risk == combined_risk.lower())
    stmt = stmt.order_by(DSPMCorrelation.detected_at.desc()).limit(limit)

    rows = (await db.execute(stmt)).scalars().all()

    # Eager-load related rows
    finding_ids   = [r.dspm_finding_id for r in rows]
    violation_ids = [r.violation_id      for r in rows]

    findings   = {f.id: f for f in (await db.execute(
        select(DSPMFinding).where(DSPMFinding.id.in_(finding_ids))
    )).scalars().all()}
    violations = {v.id: v for v in (await db.execute(
        select(Violation).where(Violation.id.in_(violation_ids))
    )).scalars().all()}

    return [
        {
            "id":             c.id,
            "risk_label":     c.risk_label,
            "combined_risk":  c.combined_risk,
            "detected_at":    c.detected_at.isoformat(),
            "dspm_finding":   {
                "id":           c.dspm_finding_id,
                "name":         findings[c.dspm_finding_id].data_store_name if c.dspm_finding_id in findings else None,
                "classifications": findings[c.dspm_finding_id].classifications.split(",") if c.dspm_finding_id in findings else [],
                "risk_level":   findings[c.dspm_finding_id].risk_level if c.dspm_finding_id in findings else None,
                "public_access":findings[c.dspm_finding_id].public_access if c.dspm_finding_id in findings else None,
            },
            "violation":      {
                "id":           c.violation_id,
                "rule_id":      violations[c.violation_id].rule_id if c.violation_id in violations else None,
                "severity":     violations[c.violation_id].severity if c.violation_id in violations else None,
                "resource_id":  violations[c.violation_id].resource_id if c.violation_id in violations else None,
            },
        }
        for c in rows
    ]


# ── Periodic refresh ─────────────────────────────────────────────────────────

@router.post("/refresh")
async def refresh_dspm(
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Re-run DSPM engine AND correlator (periodic update endpoint)."""
    async with db.begin():
        new_findings      = await run_dspm_engine(db)
        new_correlations  = await run_correlator(db)
    return {
        "status":           "ok",
        "new_findings":     new_findings,
        "new_correlations": new_correlations,
    }

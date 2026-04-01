"""
Violations API — rule-based misconfiguration findings.
"""

from typing import Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AsyncSessionLocal
from app.models.violations import Violation, ViolationRule
from app.core.violations_engine import run_violations_engine
from app.auth.dependencies import get_current_user

router = APIRouter()


async def get_db():
    async with AsyncSessionLocal() as db:
        yield db


# ── List violations ──────────────────────────────────────────────────────────

@router.get("")
async def list_violations(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status:   Optional[str] = Query(None, description="Filter by status (open/resolved/ignored)"),
    category: Optional[str] = Query(None, description="Filter by category"),
    provider: Optional[str] = Query(None, description="Filter by cloud provider"),
    limit:    int            = Query(200, le=500),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    stmt = select(Violation)
    if severity:
        stmt = stmt.where(Violation.severity == severity.lower())
    if status:
        stmt = stmt.where(Violation.status == status.lower())
    if category:
        stmt = stmt.join(ViolationRule, Violation.rule_id == ViolationRule.rule_id) \
                   .where(ViolationRule.category == category.lower())
    if provider:
        stmt = stmt.where(Violation.cloud_provider == provider.lower())

    stmt = stmt.order_by(
        Violation.severity.in_(["critical", "high", "medium", "low"]),
        Violation.detected_at.desc()
    ).limit(limit)

    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id":               v.id,
            "rule_id":          v.rule_id,
            "resource_urn":     v.resource_urn,
            "resource_id":      v.resource_id,
            "resource_type":    v.resource_type,
            "account_id":       v.account_id,
            "cloud_provider":   v.cloud_provider,
            "severity":         v.severity,
            "status":           v.status,
            "details":          v.details,
            "remediation_hint": v.remediation_hint,
            "detected_at":      v.detected_at.isoformat(),
            "resolved_at":      v.resolved_at.isoformat() if v.resolved_at else None,
        }
        for v in rows
    ]


# ── Summary ──────────────────────────────────────────────────────────────────

@router.get("/summary")
async def violations_summary(
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    all_rows = (await db.execute(select(Violation))).scalars().all()

    by_sev: dict[str, int]      = {}
    by_cat: dict[str, int]      = {}
    by_provider: dict[str, int] = {}
    open_count = 0

    # Fetch rule→category map
    rules = {r.rule_id: r for r in (await db.execute(select(ViolationRule))).scalars().all()}

    for v in all_rows:
        by_sev[v.severity]         = by_sev.get(v.severity, 0) + 1
        by_provider[v.cloud_provider] = by_provider.get(v.cloud_provider, 0) + 1
        rule = rules.get(v.rule_id)
        if rule:
            by_cat[rule.category] = by_cat.get(rule.category, 0) + 1
        if v.status == "open":
            open_count += 1

    return {
        "total":         len(all_rows),
        "open":          open_count,
        "resolved":      len(all_rows) - open_count,
        "critical":      by_sev.get("critical", 0),
        "high":          by_sev.get("high", 0),
        "medium":        by_sev.get("medium", 0),
        "low":           by_sev.get("low", 0),
        "by_category":   by_cat,
        "by_provider":   by_provider,
    }


# ── Resolve a violation ───────────────────────────────────────────────────────

@router.post("/{violation_id}/resolve")
async def resolve_violation(
    violation_id: int,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    v = (await db.execute(
        select(Violation).where(Violation.id == violation_id)
    )).scalar_one_or_none()
    if not v:
        raise HTTPException(404, "Violation not found")
    v.status      = "resolved"
    v.resolved_at = datetime.now(timezone.utc)
    await db.commit()
    return {"id": violation_id, "status": "resolved"}


# ── Trigger re-scan ───────────────────────────────────────────────────────────

@router.post("/refresh")
async def refresh_violations(
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Trigger a violations engine re-run (periodic update endpoint)."""
    async with db.begin():
        new_count = await run_violations_engine(db)
    return {"status": "ok", "new_violations": new_count}

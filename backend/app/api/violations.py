"""
Violations API — rule-based misconfiguration findings.
All queries are scoped to the requesting user's organisation (Feature 3).
Includes runbook and rollback endpoints (Feature 2).
"""

from typing import Optional
from datetime import datetime, timezone
from pathlib import Path

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AsyncSessionLocal
from app.models.violations import Violation, ViolationRule
from app.models.compliance import CloudAccount
from app.models.org import Organization
from app.core.violations_engine import run_violations_engine
from app.core.remediation import RemediationEngine
from app.core.audit import log_event
from app.auth.dependencies import get_current_user
from app.auth.scoping import get_org_scope, apply_org_scope, require_write_access

router = APIRouter()

RUNBOOKS_DIR = Path(__file__).parent.parent.parent / "runbooks"


async def get_db():
    async with AsyncSessionLocal() as db:
        yield db


# ── List violations (org-scoped) ─────────────────────────────────────────────

@router.get("")
async def list_violations(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status:   Optional[str] = Query(None, description="Filter by status (open/resolved/ignored)"),
    category: Optional[str] = Query(None, description="Filter by category"),
    provider: Optional[str] = Query(None, description="Filter by cloud provider"),
    limit:    int            = Query(200, le=500),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    scope = await get_org_scope(current_user, db)

    # Scope through Violation.account_id → CloudAccount.organization_id
    stmt = (
        select(Violation)
        .join(CloudAccount, Violation.account_id == CloudAccount.account_id, isouter=True)
    )
    stmt = apply_org_scope(stmt, CloudAccount, scope)

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
            "cve_ids":          v.cve_ids,
            "cvss_max":         v.cvss_max,
        }
        for v in rows
    ]


# ── Summary (org-scoped) ─────────────────────────────────────────────────────

@router.get("/summary")
async def violations_summary(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    scope = await get_org_scope(current_user, db)

    stmt = (
        select(Violation)
        .join(CloudAccount, Violation.account_id == CloudAccount.account_id, isouter=True)
    )
    stmt = apply_org_scope(stmt, CloudAccount, scope)
    all_rows = (await db.execute(stmt)).scalars().all()

    by_sev: dict[str, int]      = {}
    by_cat: dict[str, int]      = {}
    by_provider: dict[str, int] = {}
    open_count = 0

    rules = {r.rule_id: r for r in (await db.execute(select(ViolationRule))).scalars().all()}

    for v in all_rows:
        by_sev[v.severity]             = by_sev.get(v.severity, 0) + 1
        by_provider[v.cloud_provider]  = by_provider.get(v.cloud_provider, 0) + 1
        rule = rules.get(v.rule_id)
        if rule:
            by_cat[rule.category] = by_cat.get(rule.category, 0) + 1
        if v.status == "open":
            open_count += 1

    return {
        "total":        len(all_rows),
        "open":         open_count,
        "resolved":     len(all_rows) - open_count,
        "critical":     by_sev.get("critical", 0),
        "high":         by_sev.get("high", 0),
        "medium":       by_sev.get("medium", 0),
        "low":          by_sev.get("low", 0),
        "by_category":  by_cat,
        "by_provider":  by_provider,
    }


# ── Resolve a violation ───────────────────────────────────────────────────────

@router.post("/{violation_id}/resolve")
async def resolve_violation(
    violation_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    scope = await get_org_scope(current_user, db)
    require_write_access(scope)

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
    current_user=Depends(get_current_user),
):
    """Trigger a violations engine re-run (periodic update endpoint)."""
    scope = await get_org_scope(current_user, db)
    require_write_access(scope)

    async with db.begin():
        new_count = await run_violations_engine(db)
    return {"status": "ok", "new_violations": new_count}


# ── Runbook endpoint (Feature 2) ──────────────────────────────────────────────

@router.get("/remediations/{rule_id}/runbook")
async def get_runbook(
    rule_id: str,
    _=Depends(get_current_user),
):
    """Return the YAML runbook for a given rule_id as structured JSON."""
    # Sanitise input — only allow alphanumeric, hyphens, underscores
    safe_id = "".join(c for c in rule_id if c.isalnum() or c in "-_")
    runbook_path = RUNBOOKS_DIR / f"{safe_id}.yaml"
    if not runbook_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"No runbook found for rule '{rule_id}'. "
                   f"Available runbooks: {[f.stem for f in RUNBOOKS_DIR.glob('*.yaml')]}",
        )
    with runbook_path.open() as fh:
        data = yaml.safe_load(fh)
    return data


# ── Rollback endpoint (Feature 2) ────────────────────────────────────────────

@router.post("/remediations/{rule_id}/rollback")
async def rollback_remediation(
    rule_id: str,
    resource_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Execute the rollback_command from the runbook for a given resource.
    Respects the per-org remediation_dry_run flag.
    Requires the user to have at minimum 'auditor' role (write-gated).
    """
    scope = await get_org_scope(current_user, db)
    require_write_access(scope)

    # Fetch org-level dry_run flag
    org = None
    if current_user.organization_id:
        org = await db.get(Organization, current_user.organization_id)
    dry_run = org.remediation_dry_run if org else True

    engine = RemediationEngine(dry_run=dry_run)
    result = await engine.execute_rollback(rule_id, resource_id, current_user.organization_id)

    # Emit audit event using existing log_event helper
    await log_event(
        db=db,
        user=current_user,
        action="remediation.rollback",
        resource_type="violation_rule",
        resource_id=rule_id,
        detail={
            "resource_id": resource_id,
            "dry_run":     dry_run,
            "result":      result,
        },
    )
    await db.commit()
    return {**result, "dry_run": dry_run}

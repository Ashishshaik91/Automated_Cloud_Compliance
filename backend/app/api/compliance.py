"""
Compliance API routes — summary, posture, and check details.
"""

from typing import Annotated, Optional

import structlog
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

import time
import os
import yaml
from pathlib import Path
from app.auth.dependencies import CurrentUser, AuditorUser
from app.models.compliance import ComplianceCheck, ScanResult, CloudAccount
from app.models.database import get_db
from app.schemas.compliance import ComplianceSummary, ComplianceCheckResponse, CustomPolicyCreate

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.get("/summary", response_model=ComplianceSummary)
async def get_compliance_summary(
    _: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ComplianceSummary:
    """Return overall compliance posture summary.

    Score = aggregate pass-rate across ALL ComplianceCheck rows from the
    most-recent completed scan for EACH connected account.  This gives a
    true cross-account posture rather than whichever framework scanned last.
    """
    total_accounts_result = await db.execute(
        select(func.count()).select_from(CloudAccount).where(CloudAccount.is_active == True)
    )
    total_accounts = total_accounts_result.scalar() or 0

    # ── Step 1: latest completed scan per account ────────────────────────────
    accounts_result = await db.execute(
        select(CloudAccount).where(CloudAccount.is_active == True)
    )
    accounts = accounts_result.scalars().all()

    latest_scan_ids: list[int] = []
    latest_scan_ts = None

    for acct in accounts:
        scan_result = await db.execute(
            select(ScanResult)
            .where(
                ScanResult.account_id == acct.id,
                ScanResult.total_checks > 0,
            )
            .order_by(ScanResult.started_at.desc())
            .limit(1)
        )
        latest = scan_result.scalar_one_or_none()
        if latest:
            latest_scan_ids.append(latest.id)
            if latest_scan_ts is None or latest.started_at > latest_scan_ts:
                latest_scan_ts = latest.started_at

    # ── Step 2: aggregate pass/fail across all checks in those scans ─────────
    if latest_scan_ids:
        total_checks_q = await db.execute(
            select(func.count()).select_from(ComplianceCheck).where(
                ComplianceCheck.scan_id.in_(latest_scan_ids)
            )
        )
        pass_q = await db.execute(
            select(func.count()).select_from(ComplianceCheck).where(
                ComplianceCheck.scan_id.in_(latest_scan_ids),
                ComplianceCheck.status == "pass",
            )
        )
        crit_q = await db.execute(
            select(func.count()).select_from(ComplianceCheck).where(
                ComplianceCheck.scan_id.in_(latest_scan_ids),
                ComplianceCheck.severity == "critical",
                ComplianceCheck.status == "fail",
            )
        )
        high_q = await db.execute(
            select(func.count()).select_from(ComplianceCheck).where(
                ComplianceCheck.scan_id.in_(latest_scan_ids),
                ComplianceCheck.severity == "high",
                ComplianceCheck.status == "fail",
            )
        )
        total_checks      = total_checks_q.scalar() or 0
        total_pass        = pass_q.scalar() or 0
        critical_failures = crit_q.scalar() or 0
        high_failures     = high_q.scalar() or 0
        avg_score = round((total_pass / total_checks) * 100, 2) if total_checks else 0.0
    else:
        avg_score         = 0.0
        critical_failures = 0
        high_failures     = 0

    return ComplianceSummary(
        total_accounts=total_accounts,
        frameworks_monitored=["pci_dss", "hipaa", "gdpr", "soc2", "nist", "cis", "owasp", "custom"],
        overall_score=avg_score,
        critical_failures=critical_failures,
        high_failures=high_failures,
        last_scan_at=latest_scan_ts,
        trend="stable",
    )


@router.get("/checks", response_model=list[ComplianceCheckResponse])
async def get_compliance_checks(
    _: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    framework: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[ComplianceCheckResponse]:
    """List compliance checks with optional filtering.

    Returns checks from the most-recent completed scan for each account,
    so the policy engine table always reflects the current posture of all
    connected accounts — not just the account that last triggered a scan.
    """
    # Collect the latest scan ID per account
    accounts_result = await db.execute(
        select(CloudAccount).where(CloudAccount.is_active == True)
    )
    accounts = accounts_result.scalars().all()

    latest_scan_ids: list[int] = []
    for acct in accounts:
        scan_result = await db.execute(
            select(ScanResult)
            .where(
                ScanResult.account_id == acct.id,
                ScanResult.total_checks > 0,
            )
            .order_by(ScanResult.started_at.desc())
            .limit(1)
        )
        latest = scan_result.scalar_one_or_none()
        if latest:
            latest_scan_ids.append(latest.id)

    if not latest_scan_ids:
        return []

    stmt = select(ComplianceCheck).where(
        ComplianceCheck.scan_id.in_(latest_scan_ids)
    )
    if framework:
        stmt = stmt.where(ComplianceCheck.framework == framework)
    if status:
        stmt = stmt.where(ComplianceCheck.status == status)
    if severity:
        stmt = stmt.where(ComplianceCheck.severity == severity)
    stmt = stmt.order_by(ComplianceCheck.checked_at.desc()).offset(offset).limit(limit)

    result = await db.execute(stmt)
    checks = result.scalars().all()
    return [ComplianceCheckResponse.model_validate(c) for c in checks]


@router.post("/custom-policy")
async def create_custom_policy(
    policy: CustomPolicyCreate,
    _: AuditorUser
):
    """Dynamically generate a custom YAML and OPA Rego policy."""
    custom_dir = Path("/app/policies/custom")
    custom_dir.mkdir(parents=True, exist_ok=True)
    
    policy_id = f"custom-{policy.name.lower().replace(' ', '-')}-{int(time.time())}"
    pkg_name = f"compliance.custom.{policy_id.replace('-', '_')}"
    
    yaml_dict = {
        "policies": [
            {
                "id": policy_id,
                "name": policy.name,
                "resource_type": policy.resource_type,
                "severity": policy.severity,
                "opa_package": pkg_name,
                "remediation": "Custom policy failed.",
                "rules": [
                    {
                        "field": policy.field,
                        "operator": policy.operator
                    }
                ]
            }
        ]
    }
    
    yaml_path = custom_dir / f"{policy_id}.yaml"
    with open(yaml_path, "w", encoding="utf-8") as f:
        yaml.dump(yaml_dict, f)
        
    opa_dir = Path("/app/opa_policies")
    opa_dir.mkdir(parents=True, exist_ok=True)
    rego_path = opa_dir / f"{policy_id}.rego"
    
    with open(rego_path, "w", encoding="utf-8") as out:
        out.write(f"# OPA Custom Policy: {policy.name}\\n")
        out.write(f"package {pkg_name}\\n\\n")
        out.write("import rego.v1\\n\\n")
        out.write("default allow := false\\n\\n")
        
        out.write("allow if {\\n")
        if policy.operator == "is_true":
            out.write(f"    input.resource.{policy.field} == true\\n")
        elif policy.operator == "is_false":
            out.write(f"    input.resource.{policy.field} == false\\n")
        else:
            out.write(f"    input.resource.{policy.field} == \"{policy.operator}\"\\n")
        out.write("}\\n\\n")
        
        out.write("deny contains reason if {\\n")
        if policy.operator == "is_true":
            out.write(f"    not input.resource.{policy.field}\\n")
        elif policy.operator == "is_false":
            out.write(f"    input.resource.{policy.field}\\n")
        else:
            out.write(f"    input.resource.{policy.field} != \"{policy.operator}\"\\n")
        out.write(f"    reason := \\\"{policy.name} failed\\\"\\n")
        out.write("}\\n")

    return {
        "status": "success", 
        "policy": {
            "id": policy_id,
            "name": policy.name,
            "resource_type": policy.resource_type,
            "severity": policy.severity,
            "field": policy.field,
            "operator": policy.operator
        }
    }

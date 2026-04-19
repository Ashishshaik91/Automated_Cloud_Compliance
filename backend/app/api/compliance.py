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
    """Return overall compliance posture summary."""
    total_accounts_result = await db.execute(
        select(func.count()).select_from(CloudAccount).where(CloudAccount.is_active == True)
    )
    total_accounts = total_accounts_result.scalar() or 0

    # Latest scan per account
    latest_scan_result = await db.execute(
        select(ScanResult).order_by(ScanResult.started_at.desc()).limit(1)
    )
    latest_scan = latest_scan_result.scalar_one_or_none()

    # Live score: percentage of passing checks right now
    pass_result = await db.execute(
        select(func.count()).select_from(ComplianceCheck).where(
            ComplianceCheck.status == "pass"
        )
    )
    total_checks_result = await db.execute(
        select(func.count()).select_from(ComplianceCheck)
    )
    passing_checks = pass_result.scalar() or 0
    total_checks   = total_checks_result.scalar() or 1
    avg_score = round(100.0 * passing_checks / total_checks, 2)

    # Critical failures
    crit_result = await db.execute(
        select(func.count()).select_from(ComplianceCheck).where(
            ComplianceCheck.severity == "critical",
            ComplianceCheck.status == "fail",
        )
    )
    critical_failures = crit_result.scalar() or 0

    high_result = await db.execute(
        select(func.count()).select_from(ComplianceCheck).where(
            ComplianceCheck.severity == "high",
            ComplianceCheck.status == "fail",
        )
    )
    high_failures = high_result.scalar() or 0

    return ComplianceSummary(
        total_accounts=total_accounts,
        frameworks_monitored=["pci_dss", "hipaa", "gdpr", "soc2", "nist", "cis", "owasp", "custom"],
        overall_score=round(avg_score, 2),
        critical_failures=critical_failures,
        high_failures=high_failures,
        last_scan_at=latest_scan.started_at if latest_scan else None,
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
    """List compliance checks with optional filtering."""
    stmt = select(ComplianceCheck)
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

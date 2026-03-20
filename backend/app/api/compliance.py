"""
Compliance API routes — summary, posture, and check details.
"""

from typing import Annotated, Optional

import structlog
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import CurrentUser
from app.models.compliance import ComplianceCheck, ScanResult, CloudAccount
from app.models.database import get_db
from app.schemas.compliance import ComplianceSummary, ComplianceCheckResponse

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

    # Average compliance score
    avg_score_result = await db.execute(
        select(func.avg(ScanResult.compliance_score))
    )
    avg_score = float(avg_score_result.scalar() or 0.0)

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
        frameworks_monitored=["pci_dss", "hipaa", "gdpr", "soc2"],
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

"""
Scan management API routes.
Trigger scans, view scan history, and get detailed results.
All data is scoped to the requesting user's organisation (Feature 3).
"""

from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import CurrentUser
from app.auth.scoping import OrgScope, apply_org_scope, get_org_scope, require_write_access
from app.core.scanner import run_scheduled_scan
from app.models.compliance import CloudAccount, ScanResult
from app.models.database import get_db
from app.schemas.compliance import ScanResultResponse, ScanTriggerRequest, ScanWithChecksResponse

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.post("/trigger", status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan(
    body: ScanTriggerRequest,
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Trigger a compliance scan for a cloud account (async via Celery)."""
    scope = await get_org_scope(current_user, db)
    require_write_access(scope)  # Auditors cannot trigger scans

    # Fetch account and validate org membership
    account_result = await db.execute(
        select(CloudAccount).where(CloudAccount.id == body.account_id)
    )
    account = account_result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    # Enforce org boundary: non-admins may only scan accounts in their org(s)
    if not scope.is_admin and account.organization_id not in scope.org_ids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have access to this cloud account.",
        )

    # Dispatch Celery task — always carry organization_id in task payload
    task = run_scheduled_scan.delay(
        body.account_id,
        body.framework,
        organization_id=account.organization_id,
        terraform_state_path=body.terraform_state_path,
        terraform_working_dir=body.terraform_working_dir,
    )
    logger.info(
        "Scan triggered",
        account_id=body.account_id,
        framework=body.framework,
        task_id=task.id,
        user_id=current_user.id,
        org_id=account.organization_id,
        terraform_state_path=body.terraform_state_path,
        terraform_working_dir=body.terraform_working_dir,
    )
    return {
        "task_id": task.id,
        "message": f"Scan triggered for account {body.account_id}",
        "framework": body.framework,
    }


@router.get("/", response_model=list[ScanResultResponse])
async def list_scans(
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    account_id: int | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[ScanResultResponse]:
    """List scan results scoped to the user's organisation."""
    scope = await get_org_scope(current_user, db)

    # Join ScanResult → CloudAccount to apply org filter
    stmt = (
        select(ScanResult)
        .join(CloudAccount, ScanResult.account_id == CloudAccount.id)
        .order_by(ScanResult.started_at.desc())
    )
    stmt = apply_org_scope(stmt, CloudAccount, scope)

    if account_id:
        stmt = stmt.where(ScanResult.account_id == account_id)

    stmt = stmt.offset(offset).limit(limit)
    result = await db.execute(stmt)
    scans = result.scalars().all()
    return [ScanResultResponse.model_validate(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanWithChecksResponse)
async def get_scan_detail(
    scan_id: int,
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ScanWithChecksResponse:
    """Get detailed scan results. Enforces org isolation on the result."""
    from sqlalchemy.orm import selectinload

    scope = await get_org_scope(current_user, db)

    result = await db.execute(
        select(ScanResult)
        .options(selectinload(ScanResult.checks))
        .join(CloudAccount, ScanResult.account_id == CloudAccount.id)
        .where(ScanResult.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Validate org membership post-fetch
    account = await db.get(CloudAccount, scan.account_id)
    if not scope.is_admin and account and account.organization_id not in scope.org_ids:
        raise HTTPException(status_code=404, detail="Scan not found")  # 404 not 403 to avoid leaking IDs

    return ScanWithChecksResponse.model_validate(scan)

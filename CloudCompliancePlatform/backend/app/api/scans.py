"""
Scan management API routes.
Trigger scans, view scan history, and get detailed results.
"""

from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import CurrentUser
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
    account_result = await db.execute(
        select(CloudAccount).where(CloudAccount.id == body.account_id)
    )
    account = account_result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    # Dispatch Celery task
    task = run_scheduled_scan.delay(body.account_id, body.framework)
    logger.info(
        "Scan triggered",
        account_id=body.account_id,
        framework=body.framework,
        task_id=task.id,
        user_id=current_user.id,
    )
    return {
        "task_id": task.id,
        "message": f"Scan triggered for account {body.account_id}",
        "framework": body.framework,
    }


@router.get("/", response_model=list[ScanResultResponse])
async def list_scans(
    _: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    account_id: int | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[ScanResultResponse]:
    """List scan results."""
    stmt = select(ScanResult).order_by(ScanResult.started_at.desc())
    if account_id:
        stmt = stmt.where(ScanResult.account_id == account_id)
    stmt = stmt.offset(offset).limit(limit)
    result = await db.execute(stmt)
    scans = result.scalars().all()
    return [ScanResultResponse.model_validate(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanWithChecksResponse)
async def get_scan_detail(
    scan_id: int,
    _: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ScanWithChecksResponse:
    """Get detailed scan results including all compliance checks."""
    from sqlalchemy.orm import selectinload
    result = await db.execute(
        select(ScanResult)
        .options(selectinload(ScanResult.checks))
        .where(ScanResult.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanWithChecksResponse.model_validate(scan)

"""
Cloud Accounts management API.
Register, list, and manage cloud accounts for compliance scanning.
"""

from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import AdminUser, CurrentUser
from app.models.compliance import CloudAccount
from app.models.database import get_db
from app.schemas.compliance import CloudAccountCreate, CloudAccountResponse

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.post("/", response_model=CloudAccountResponse, status_code=status.HTTP_201_CREATED)
async def create_cloud_account(
    body: CloudAccountCreate,
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> CloudAccountResponse:
    """Register a new cloud account for compliance monitoring (admin only)."""
    account = CloudAccount(
        name=body.name,
        provider=body.provider,
        account_id=body.account_id,
        region=body.region,
    )
    db.add(account)
    await db.flush()
    logger.info("Cloud account registered", account_id=account.id, provider=body.provider)
    return CloudAccountResponse.model_validate(account)


@router.get("/", response_model=list[CloudAccountResponse])
async def list_cloud_accounts(
    _: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[CloudAccountResponse]:
    """List all registered cloud accounts."""
    result = await db.execute(
        select(CloudAccount).where(CloudAccount.is_active == True)
    )
    accounts = result.scalars().all()
    return [CloudAccountResponse.model_validate(a) for a in accounts]


@router.delete("/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
async def disable_cloud_account(
    account_id: int,
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Deactivate a cloud account (soft delete)."""
    result = await db.execute(
        select(CloudAccount).where(CloudAccount.id == account_id)
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    account.is_active = False
    logger.info("Cloud account deactivated", account_id=account_id, user_id=current_user.id)

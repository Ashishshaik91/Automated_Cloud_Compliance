"""
Cloud Accounts management API.
Register, list, and manage cloud accounts for compliance scanning.
"""

from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import AdminUser, CurrentUser
from app.core.audit import log_event
from app.models.compliance import CloudAccount
from app.models.database import get_db
from app.models.org import UserAccountRole
from app.schemas.compliance import CloudAccountCreate, CloudAccountResponse

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.post("/", response_model=CloudAccountResponse, status_code=status.HTTP_201_CREATED)
async def create_cloud_account(
    body: CloudAccountCreate,
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
) -> CloudAccountResponse:
    """Register a new cloud account for compliance monitoring (admin only)."""
    account = CloudAccount(
        name=body.name,
        provider=body.provider,
        account_id=body.account_id,
        region=body.region,
        owner_user_id=current_user.id,
    )
    db.add(account)
    await db.flush()
    # Auto-assign admin role to creator on this account
    assignment = UserAccountRole(
        user_id=current_user.id,
        cloud_account_id=account.id,
        role="admin",
        granted_by=current_user.id,
    )
    db.add(assignment)
    await db.flush()
    await log_event(
        db, current_user, "account.create",
        resource_type="CloudAccount", resource_id=str(account.id),
        detail={"name": account.name, "provider": account.provider},
        request=request,
    )
    logger.info("Cloud account registered", account_id=account.id, provider=body.provider)
    return CloudAccountResponse.model_validate(account)


@router.get("/", response_model=list[CloudAccountResponse])
async def list_cloud_accounts(
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[CloudAccountResponse]:
    """List cloud accounts visible to the current user.

    - Admins see all active accounts.
    - All other roles see only accounts they have an active, non-expired role assignment on.
    """
    if current_user.role == "admin":
        result = await db.execute(
            select(CloudAccount).where(CloudAccount.is_active == True)
        )
        accounts = result.scalars().all()
    else:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        # Join through UserAccountRole to get only assigned, active, non-expired accounts
        result = await db.execute(
            select(CloudAccount)
            .join(UserAccountRole, UserAccountRole.cloud_account_id == CloudAccount.id)
            .where(
                UserAccountRole.user_id == current_user.id,
                UserAccountRole.is_active == True,
                CloudAccount.is_active == True,
                (UserAccountRole.expires_at == None) | (UserAccountRole.expires_at > now),
            )
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

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
from app.auth.scoping import apply_org_scope, get_org_scope, require_write_access
from app.core.audit import log_event
from app.models.compliance import CloudAccount
from app.models.database import get_db
from app.models.org import UserAccountRole
from app.schemas.compliance import CloudAccountCreate, CloudAccountResponse

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.post("", response_model=CloudAccountResponse, status_code=status.HTTP_201_CREATED)
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
        # Inherit the creating admin's org so the account is immediately scoped
        organization_id=current_user.organization_id,
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
        detail={"name": account.name, "provider": account.provider,
                "organization_id": account.organization_id},
        request=request,
    )
    logger.info("Cloud account registered", account_id=account.id, provider=body.provider)
    return CloudAccountResponse.model_validate(account)


@router.get("", response_model=list[CloudAccountResponse])
async def list_cloud_accounts(
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[CloudAccountResponse]:
    """List cloud accounts visible to the current user.

    Access tiers:
    - Admin   → all active accounts (no filter)
    - Auditor → accounts in explicitly assigned orgs only
    - Dev/Viewer → accounts in own org only, AND must have an active role assignment
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    scope = await get_org_scope(current_user, db)

    if scope.is_admin:
        # Admin sees every active account
        result = await db.execute(
            select(CloudAccount).where(CloudAccount.is_active == True)
        )
        return [CloudAccountResponse.model_validate(a) for a in result.scalars().all()]

    if scope.is_read_only:
        # Auditor: all accounts in assigned orgs (no role-assignment requirement)
        stmt = (
            select(CloudAccount)
            .where(CloudAccount.is_active == True)
        )
        stmt = apply_org_scope(stmt, CloudAccount, scope)
        result = await db.execute(stmt)
        return [CloudAccountResponse.model_validate(a) for a in result.scalars().all()]

    # Dev / viewer: must have an active, non-expired role assignment AND be in own org
    stmt = (
        select(CloudAccount)
        .join(UserAccountRole, UserAccountRole.cloud_account_id == CloudAccount.id)
        .where(
            UserAccountRole.user_id == current_user.id,
            UserAccountRole.is_active == True,
            CloudAccount.is_active == True,
            (UserAccountRole.expires_at == None) | (UserAccountRole.expires_at > now),
        )
    )
    stmt = apply_org_scope(stmt, CloudAccount, scope)
    result = await db.execute(stmt)
    return [CloudAccountResponse.model_validate(a) for a in result.scalars().all()]


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

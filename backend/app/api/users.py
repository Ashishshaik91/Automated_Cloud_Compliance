"""
User management API — admin-only endpoints for creating, listing, and managing users
and their time-limited per-account role assignments.
"""

from datetime import datetime, timezone
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import AdminUser, CurrentUser
from app.auth.jwt import hash_password
from app.core.audit import log_event
from app.models.database import get_db
from app.models.org import UserAccountRole
from app.models.user import User
from app.schemas.auth import AdminUserCreate, UserResponse
from app.schemas.org import UserAccountRoleCreate, UserAccountRoleResponse

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: AdminUserCreate,
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
) -> UserResponse:
    """Create a new user with a specific role. Admin only."""
    existing = await User.get_by_email(db, body.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered.")

    user = User(
        email=body.email.lower().strip(),
        full_name=body.full_name,
        hashed_password=hash_password(body.password),
        role=body.role,
        organization_id=body.organization_id,
    )
    db.add(user)
    await db.flush()

    await log_event(
        db, current_user, "user.create",
        resource_type="User", resource_id=str(user.id),
        detail={"email": user.email, "role": user.role},
        request=request,
    )
    logger.info("User created by admin", new_user_id=user.id, role=user.role)
    return UserResponse.model_validate(user)


@router.get("", response_model=list[UserResponse])
async def list_users(
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[UserResponse]:
    """List all users. Admin only."""
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return [UserResponse.model_validate(u) for u in result.scalars().all()]


@router.patch("/{user_id}/deactivate", response_model=UserResponse)
async def deactivate_user(
    user_id: int,
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
) -> UserResponse:
    """Deactivate a user account. Admin only."""
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account.")
    user = await User.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user.is_active = False
    await db.flush()
    await log_event(
        db, current_user, "user.deactivate",
        resource_type="User", resource_id=str(user_id), request=request,
    )
    return UserResponse.model_validate(user)


# ─── Per-account role assignments ─────────────────────────────────────────────

@router.post("/{user_id}/roles", response_model=UserAccountRoleResponse, status_code=201)
async def assign_role(
    user_id: int,
    body: UserAccountRoleCreate,
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
) -> UserAccountRoleResponse:
    """
    Assign (or update) a user's role on a specific cloud account.
    Optionally set expires_at for time-limited access.
    """
    user = await User.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Upsert — update if assignment already exists
    existing = await UserAccountRole.get_for_user_and_account(db, user_id, body.cloud_account_id)
    if existing:
        existing.role = body.role
        existing.expires_at = body.expires_at
        existing.granted_by = current_user.id
        existing.granted_at = datetime.now(timezone.utc)
        existing.is_active = True
        assignment = existing
    else:
        assignment = UserAccountRole(
            user_id=user_id,
            cloud_account_id=body.cloud_account_id,
            role=body.role,
            expires_at=body.expires_at,
            granted_by=current_user.id,
        )
        db.add(assignment)

    await db.flush()
    await log_event(
        db, current_user, "role.assign",
        resource_type="UserAccountRole", resource_id=str(assignment.id),
        detail={
            "target_user_id": user_id,
            "account_id": body.cloud_account_id,
            "role": body.role,
            "expires_at": body.expires_at.isoformat() if body.expires_at else None,
        },
        request=request,
    )

    response = UserAccountRoleResponse.model_validate(assignment)
    response.is_expired = assignment.is_expired
    return response


@router.delete("/{user_id}/roles/{account_id}", status_code=204)
async def revoke_role(
    user_id: int,
    account_id: int,
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
) -> None:
    """Immediately revoke a user's role on a specific account. Admin only."""
    assignment = await UserAccountRole.get_for_user_and_account(db, user_id, account_id)
    if not assignment:
        raise HTTPException(status_code=404, detail="No active role assignment found.")
    assignment.is_active = False
    await db.flush()
    await log_event(
        db, current_user, "role.revoke",
        resource_type="UserAccountRole", resource_id=str(assignment.id),
        detail={"target_user_id": user_id, "account_id": account_id},
        request=request,
    )


@router.get("/{user_id}/roles", response_model=list[UserAccountRoleResponse])
async def list_user_roles(
    user_id: int,
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[UserAccountRoleResponse]:
    """List all role assignments (active + expired) for a user. Admin only."""
    assignments = await UserAccountRole.get_all_for_user(db, user_id)
    responses = []
    for a in assignments:
        r = UserAccountRoleResponse.model_validate(a)
        r.is_expired = a.is_expired
        responses.append(r)
    return responses

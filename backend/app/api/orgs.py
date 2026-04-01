"""
Organization management API.
Admin-only: create orgs, list org tree, assign users to accounts within orgs.
"""

from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import AdminUser
from app.core.audit import log_event
from app.models.database import get_db
from app.models.org import Organization
from app.schemas.org import OrgCreate, OrgResponse

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.post("/", response_model=OrgResponse, status_code=status.HTTP_201_CREATED)
async def create_org(
    body: OrgCreate,
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
) -> OrgResponse:
    """Create a new organization. Admin only."""
    # Validate parent exists if specified
    if body.parent_org_id:
        parent = await db.get(Organization, body.parent_org_id)
        if not parent:
            raise HTTPException(status_code=404, detail="Parent organization not found.")

    org = Organization(name=body.name, parent_org_id=body.parent_org_id)
    db.add(org)
    await db.flush()

    await log_event(
        db, current_user, "org.create",
        resource_type="Organization", resource_id=str(org.id),
        detail={"name": org.name, "parent_org_id": org.parent_org_id},
        request=request,
    )
    return OrgResponse.model_validate(org)


@router.get("/", response_model=list[OrgResponse])
async def list_orgs(
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[OrgResponse]:
    """List all organizations. Admin only."""
    result = await db.execute(select(Organization).order_by(Organization.id))
    return [OrgResponse.model_validate(o) for o in result.scalars().all()]


@router.delete("/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_org(
    org_id: int,
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
) -> None:
    """Delete an organization (only if it has no child orgs). Admin only."""
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found.")

    # Check for children
    children = await db.execute(
        select(Organization).where(Organization.parent_org_id == org_id)
    )
    if children.scalar_one_or_none():
        raise HTTPException(
            status_code=400,
            detail="Cannot delete organization with child organizations. Remove children first.",
        )

    await db.delete(org)
    await log_event(
        db, current_user, "org.delete",
        resource_type="Organization", resource_id=str(org_id),
        request=request,
    )

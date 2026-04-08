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
from app.models.org import AuditorOrgAssignment, Organization
from app.models.user import User
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


# ── Auditor org assignments ─────────────────────────────────────────────────────

@router.post(
    "/{org_id}/auditors",
    status_code=status.HTTP_201_CREATED,
    summary="Grant an auditor read access to an organisation",
)
async def assign_auditor_to_org(
    org_id: int,
    user_id: int,
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
) -> dict:
    """
    Grant an auditor-role user read access to the specified organisation.
    Only admins can perform this action.
    The target user must have role='auditor'.
    """
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found.")

    auditor = await User.get_by_id(db, user_id)
    if not auditor:
        raise HTTPException(status_code=404, detail="User not found.")
    if auditor.role != "auditor":
        raise HTTPException(
            status_code=400,
            detail=f"User {user_id} has role '{auditor.role}'. Only 'auditor' users can be assigned.",
        )

    # Idempotent — return existing assignment if already granted
    existing = (await db.execute(
        select(AuditorOrgAssignment).where(
            AuditorOrgAssignment.auditor_user_id == user_id,
            AuditorOrgAssignment.organization_id == org_id,
        )
    )).scalar_one_or_none()

    if existing:
        return {
            "id": existing.id,
            "auditor_user_id": user_id,
            "organization_id": org_id,
            "granted_at": existing.granted_at.isoformat(),
            "message": "Assignment already exists.",
        }

    assignment = AuditorOrgAssignment(
        auditor_user_id=user_id,
        organization_id=org_id,
        granted_by=current_user.id,
    )
    db.add(assignment)
    await db.flush()

    await log_event(
        db, current_user, "auditor.org.assign",
        resource_type="AuditorOrgAssignment", resource_id=str(assignment.id),
        detail={"auditor_user_id": user_id, "organization_id": org_id},
        request=request,
    )
    logger.info("Auditor assigned to org", auditor_id=user_id, org_id=org_id)
    return {
        "id": assignment.id,
        "auditor_user_id": user_id,
        "organization_id": org_id,
        "granted_by": current_user.id,
        "granted_at": assignment.granted_at.isoformat(),
    }


@router.delete(
    "/{org_id}/auditors/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke an auditor's access to an organisation",
)
async def revoke_auditor_from_org(
    org_id: int,
    user_id: int,
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
) -> None:
    """Revoke an auditor's org-level read access. Admin only."""
    assignment = (await db.execute(
        select(AuditorOrgAssignment).where(
            AuditorOrgAssignment.auditor_user_id == user_id,
            AuditorOrgAssignment.organization_id == org_id,
        )
    )).scalar_one_or_none()

    if not assignment:
        raise HTTPException(status_code=404, detail="No auditor assignment found.")

    await db.delete(assignment)
    await log_event(
        db, current_user, "auditor.org.revoke",
        resource_type="AuditorOrgAssignment", resource_id=str(assignment.id),
        detail={"auditor_user_id": user_id, "organization_id": org_id},
        request=request,
    )
    logger.info("Auditor revoked from org", auditor_id=user_id, org_id=org_id)


@router.get(
    "/{org_id}/auditors",
    summary="List auditors assigned to an organisation",
)
async def list_org_auditors(
    org_id: int,
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[dict]:
    """List all auditors with access to the specified organisation. Admin only."""
    rows = (await db.execute(
        select(AuditorOrgAssignment).where(
            AuditorOrgAssignment.organization_id == org_id
        ).order_by(AuditorOrgAssignment.granted_at.desc())
    )).scalars().all()
    return [
        {
            "id": r.id,
            "auditor_user_id": r.auditor_user_id,
            "organization_id": r.organization_id,
            "granted_by": r.granted_by,
            "granted_at": r.granted_at.isoformat(),
        }
        for r in rows
    ]

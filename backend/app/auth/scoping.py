"""
Org-scoped query helpers — Feature 3: Multi-Account Org Isolation.

Three-tier access hierarchy:
  Admin   → sees all organisations (no WHERE filter)
  Auditor → sees only orgs they are explicitly assigned to (read-only)
  Customer (dev/viewer) → sees only their own organisation

Usage in an API route:
    from app.auth.scoping import apply_org_scope

    stmt = select(ScanResult)
    stmt = apply_org_scope(stmt, ScanResult, current_user, db)
    rows = (await db.execute(stmt)).scalars().all()
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User

logger = structlog.get_logger(__name__)


class MissingOrgContextError(RuntimeError):
    """Raised when a Celery task is invoked without an organization_id."""


@dataclass
class OrgScope:
    """Describes the set of organisations a user is allowed to access."""
    mode: str           # "all" | "assigned" | "own"
    org_ids: list[int] = field(default_factory=list)

    @property
    def is_admin(self) -> bool:
        return self.mode == "all"

    @property
    def is_read_only(self) -> bool:
        """Auditors have read-only access across their assigned orgs."""
        return self.mode == "assigned"


async def get_org_scope(user: User, db: AsyncSession) -> OrgScope:
    """
    Return an OrgScope describing what the user may access.

    - admin   → OrgScope(mode="all")
    - auditor → OrgScope(mode="assigned", org_ids=[...])
    - dev/viewer (customer) → OrgScope(mode="own", org_ids=[user.organization_id])
    """
    if user.role == "admin":
        return OrgScope(mode="all")

    if user.role == "auditor":
        # Fetch the orgs explicitly assigned to this auditor
        from app.models.org import AuditorOrgAssignment
        result = await db.execute(
            select(AuditorOrgAssignment.organization_id).where(
                AuditorOrgAssignment.auditor_user_id == user.id
            )
        )
        assigned_ids = list(result.scalars().all())
        # Always include own org if set
        if user.organization_id and user.organization_id not in assigned_ids:
            assigned_ids.append(user.organization_id)
        return OrgScope(mode="assigned", org_ids=assigned_ids)

    # dev / viewer — own org only
    if not user.organization_id:
        logger.warning(
            "User has no organization_id set",
            user_id=user.id,
            role=user.role,
        )
        # Still return own-mode with empty list; caller should handle gracefully
        return OrgScope(mode="own", org_ids=[])

    return OrgScope(mode="own", org_ids=[user.organization_id])


def apply_org_scope(stmt: Any, model: Any, scope: OrgScope) -> Any:
    """
    Inject an organization_id WHERE clause into a SQLAlchemy select statement.

    Args:
        stmt:  The SQLAlchemy select() statement to filter.
        model: The SQLAlchemy model class that has an `organization_id` column.
        scope: The OrgScope returned by get_org_scope().

    Returns:
        The filtered statement.
    """
    if scope.mode == "all":
        return stmt  # Admin — no filter

    if not scope.org_ids:
        # No accessible orgs → return nothing
        return stmt.where(model.organization_id == -1)

    if len(scope.org_ids) == 1:
        return stmt.where(model.organization_id == scope.org_ids[0])

    return stmt.where(model.organization_id.in_(scope.org_ids))


def require_write_access(scope: OrgScope) -> None:
    """
    Raise 403 if the user only has read-only (Auditor) access.
    Call this before any mutation operation.
    """
    if scope.is_read_only:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Auditors have read-only access. Write operations are not permitted.",
        )


def require_org_context(organization_id: int | None) -> int:
    """
    Validate that a Celery task was dispatched with an org context.
    Raises MissingOrgContextError if organization_id is None.
    """
    if organization_id is None:
        raise MissingOrgContextError(
            "Task invoked without organization_id. "
            "All async tasks must carry org context from the dispatching HTTP request."
        )
    return organization_id

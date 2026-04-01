"""
Audit logging helper.
Call log_event() from any state-mutating endpoint to write an immutable audit trail.
Viewer GET actions are intentionally excluded (too noisy, read-only).
"""

from typing import Any, Optional

import structlog
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.user import User

logger = structlog.get_logger(__name__)


async def log_event(
    db: AsyncSession,
    user: User,
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    detail: Optional[dict[str, Any]] = None,
    request: Optional[Request] = None,
) -> None:
    """
    Write an immutable audit log entry.

    Args:
        db:            Active async DB session (will be flushed, not committed).
        user:          The authenticated user performing the action.
        action:        Dot-namespaced action string, e.g. "user.create", "role.assign".
        resource_type: Entity type affected, e.g. "User", "CloudAccount".
        resource_id:   String ID of the affected resource.
        detail:        Arbitrary JSON payload (before/after values, params, etc.).
        request:       FastAPI Request object — used to extract the client IP.
    """
    ip: Optional[str] = None
    if request is not None:
        # Respect X-Forwarded-For when running behind a proxy/nginx
        forwarded_for = request.headers.get("x-forwarded-for")
        ip = forwarded_for.split(",")[0].strip() if forwarded_for else request.client.host if request.client else None

    entry = AuditLog(
        user_id=user.id,
        user_email=user.email,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        detail=detail,
        ip_address=ip,
    )
    db.add(entry)
    await db.flush()
    logger.info(
        "audit_event",
        user_id=user.id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
    )

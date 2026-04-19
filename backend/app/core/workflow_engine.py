"""
Workflow Engine — creates, approves, rejects, and executes approval requests.

4-eyes rule: requester cannot approve their own request.
Time-limited: requests expire after DEFAULT_EXPIRY_HOURS hours.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.workflow import ApprovalRequest, ApprovalStatus
from app.models.user import User

logger = structlog.get_logger(__name__)

DEFAULT_EXPIRY_HOURS = 24
APPROVER_ROLES = {"admin", "auditor"}


async def create_approval_request(
    db: AsyncSession,
    *,
    requester: User,
    action_type: str,
    title: str,
    description: str = "",
    action_payload: dict[str, Any] | None = None,
    risk_level: str = "high",
    expiry_hours: int = DEFAULT_EXPIRY_HOURS,
) -> ApprovalRequest:
    """Create a new pending approval request."""
    req = ApprovalRequest(
        id=str(uuid.uuid4()),
        title=title,
        description=description,
        action_type=action_type,
        action_payload=action_payload or {},
        risk_level=risk_level,
        status=ApprovalStatus.PENDING,
        org_id=requester.organization_id,
        requester_id=requester.id,
        requested_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=expiry_hours),
    )
    db.add(req)
    await db.flush()
    logger.info(
        "Approval request created",
        request_id=req.id,
        action_type=action_type,
        risk_level=risk_level,
        requester_id=requester.id,
    )
    return req


async def get_request(db: AsyncSession, request_id: str) -> ApprovalRequest | None:
    result = await db.execute(
        select(ApprovalRequest).where(ApprovalRequest.id == request_id)
    )
    return result.scalar_one_or_none()


async def approve_request(
    db: AsyncSession,
    *,
    approver: User,
    request_id: str,
    notes: str = "",
) -> ApprovalRequest:
    """Approve a pending request. Enforces 4-eyes and role checks."""
    req = await get_request(db, request_id)
    if not req:
        raise ValueError(f"Request {request_id} not found")
    if req.status != ApprovalStatus.PENDING:
        raise ValueError(f"Request is already {req.status}")
    if req.is_expired:
        req.status = ApprovalStatus.EXPIRED
        await db.flush()
        raise ValueError("Request has expired")
    if req.requester_id == approver.id:
        raise PermissionError("Cannot approve your own request (4-eyes rule)")
    if approver.role not in APPROVER_ROLES:
        raise PermissionError(f"Role '{approver.role}' cannot approve requests")

    req.status = ApprovalStatus.APPROVED
    req.approver_id = approver.id
    req.reviewed_at = datetime.now(timezone.utc)
    req.notes = notes
    await db.flush()
    logger.info("Request approved", request_id=req.id, approver_id=approver.id)
    return req


async def reject_request(
    db: AsyncSession,
    *,
    approver: User,
    request_id: str,
    notes: str = "",
) -> ApprovalRequest:
    """Reject a pending request."""
    req = await get_request(db, request_id)
    if not req:
        raise ValueError(f"Request {request_id} not found")
    if req.status != ApprovalStatus.PENDING:
        raise ValueError(f"Request is already {req.status}")
    if approver.role not in APPROVER_ROLES:
        raise PermissionError(f"Role '{approver.role}' cannot reject requests")

    req.status = ApprovalStatus.REJECTED
    req.approver_id = approver.id
    req.reviewed_at = datetime.now(timezone.utc)
    req.notes = notes
    await db.flush()
    logger.info("Request rejected", request_id=req.id, approver_id=approver.id)
    return req


async def cancel_request(
    db: AsyncSession,
    *,
    requester: User,
    request_id: str,
) -> ApprovalRequest:
    """Allow the original requester to cancel a pending request."""
    req = await get_request(db, request_id)
    if not req:
        raise ValueError(f"Request {request_id} not found")
    if req.requester_id != requester.id and requester.role != "admin":
        raise PermissionError("Only the requester or an admin can cancel")
    if req.status != ApprovalStatus.PENDING:
        raise ValueError(f"Request is already {req.status}")

    req.status = ApprovalStatus.CANCELLED
    req.reviewed_at = datetime.now(timezone.utc)
    await db.flush()
    logger.info("Request cancelled", request_id=req.id, requester_id=requester.id)
    return req


async def execute_approved_request(
    db: AsyncSession,
    req: ApprovalRequest,
) -> dict[str, Any]:
    """
    Execute an approved request by dispatching to the remediation engine.
    Marks the request as EXECUTED with the result.
    """
    from app.core.remediation import execute_remediation_action  # avoid circular import

    if req.status != ApprovalStatus.APPROVED:
        raise ValueError(f"Cannot execute request in state '{req.status}'")

    try:
        result = await execute_remediation_action(
            action_type=req.action_type,
            payload=req.action_payload or {},
        )
        req.status = ApprovalStatus.EXECUTED
        req.execution_result = {"status": "success", "result": result}

        # Auto-resolve the matching violation so the dashboard reflects immediately
        if req.action_type == "remediation":
            payload = req.action_payload or {}
            rule_id     = payload.get("rule_id", "")
            resource_id = payload.get("resource_id", "")
            if rule_id and resource_id:
                from app.models.violations import Violation
                from sqlalchemy import update as sa_update
                await db.execute(
                    sa_update(Violation)
                    .where(
                        Violation.rule_id    == rule_id,
                        Violation.resource_id == resource_id,
                        Violation.status     == "open",
                    )
                    .values(
                        status      = "resolved",
                        resolved_at = datetime.now(timezone.utc),
                    )
                )
                logger.info(
                    "Violation auto-resolved after workflow execution",
                    rule_id=rule_id, resource_id=resource_id,
                )
    except Exception as e:
        req.execution_result = {"status": "error", "error": str(e)}
        logger.error("Request execution failed", request_id=req.id, error=str(e))

    await db.flush()
    return req.execution_result


async def expire_stale_requests(db: AsyncSession) -> int:
    """
    Mark all PENDING requests that have passed their expires_at as EXPIRED.
    Called by Celery beat every hour.
    Returns the count of expired requests.
    """
    now = datetime.now(timezone.utc)
    result = await db.execute(
        update(ApprovalRequest)
        .where(
            ApprovalRequest.status == ApprovalStatus.PENDING,
            ApprovalRequest.expires_at < now,
        )
        .values(status=ApprovalStatus.EXPIRED)
        .returning(ApprovalRequest.id)
    )
    expired_ids = result.fetchall()
    count = len(expired_ids)
    if count:
        logger.info("Expired stale approval requests", count=count)
    return count

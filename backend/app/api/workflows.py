"""
Workflows API — CRUD and state transitions for approval requests.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import CurrentUser, require_roles
from app.models.user import User
from app.core.workflow_engine import (
    approve_request,
    cancel_request,
    create_approval_request,
    execute_approved_request,
    expire_stale_requests,
    get_request,
    reject_request,
)
from app.models.database import get_db
from app.models.workflow import ApprovalRequest, ApprovalStatus

router = APIRouter()
logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Pydantic schemas (inline — small enough not to warrant a separate file)
# ---------------------------------------------------------------------------

class ApprovalRequestCreate(BaseModel):
    title: str = Field(..., max_length=500)
    description: str = ""
    action_type: str = Field(..., description="e.g. 'remediation', 'policy_change'")
    action_payload: dict[str, Any] = {}
    risk_level: str = Field("high", pattern="^(critical|high|medium)$")
    expiry_hours: int = Field(24, ge=1, le=168)


class ApprovalDecision(BaseModel):
    notes: str = ""


class ApprovalRequestOut(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    title: str
    description: Optional[str]
    action_type: str
    risk_level: str
    status: str
    org_id: int
    requester_id: int
    approver_id: Optional[int]
    requested_at: datetime
    expires_at: Optional[datetime]
    reviewed_at: Optional[datetime]
    notes: Optional[str]
    execution_result: Optional[dict]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/requests",
    response_model=ApprovalRequestOut,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a new approval request",
)
async def submit_request(
    body: ApprovalRequestCreate,
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ApprovalRequestOut:
    if current_user.role not in ("admin",):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators may submit approval requests.",
        )
    req = await create_approval_request(
        db,
        requester=current_user,
        action_type=body.action_type,
        title=body.title,
        description=body.description,
        action_payload=body.action_payload,
        risk_level=body.risk_level,
        expiry_hours=body.expiry_hours,
    )
    await db.commit()
    return ApprovalRequestOut.model_validate(req)


@router.get(
    "/requests",
    response_model=list[ApprovalRequestOut],
    summary="List approval requests (scoped by role)",
)
async def list_requests(
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(50, le=200),
) -> list[ApprovalRequestOut]:
    stmt = select(ApprovalRequest)

    # Admins/auditors see all org requests; devs/viewers see only their own
    if current_user.role in ("admin", "auditor"):
        stmt = stmt.where(ApprovalRequest.org_id == current_user.organization_id)
    else:
        stmt = stmt.where(ApprovalRequest.requester_id == current_user.id)

    if status_filter:
        stmt = stmt.where(ApprovalRequest.status == status_filter)

    stmt = stmt.order_by(ApprovalRequest.requested_at.desc()).limit(limit)
    result = await db.execute(stmt)
    return [ApprovalRequestOut.model_validate(r) for r in result.scalars().all()]


@router.get("/requests/{request_id}", response_model=ApprovalRequestOut)
async def get_request_detail(
    request_id: str,
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ApprovalRequestOut:
    req = await get_request(db, request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")
    if req.org_id != current_user.organization_id and current_user.role not in ("admin",):
        raise HTTPException(status_code=403, detail="Not in your org")
    return ApprovalRequestOut.model_validate(req)


@router.post("/requests/{request_id}/approve", response_model=ApprovalRequestOut)
async def approve(
    request_id: str,
    body: ApprovalDecision,
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ApprovalRequestOut:
    try:
        req = await approve_request(db, approver=current_user, request_id=request_id, notes=body.notes)
        await db.commit()
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return ApprovalRequestOut.model_validate(req)


@router.post("/requests/{request_id}/reject", response_model=ApprovalRequestOut)
async def reject(
    request_id: str,
    body: ApprovalDecision,
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ApprovalRequestOut:
    try:
        req = await reject_request(db, approver=current_user, request_id=request_id, notes=body.notes)
        await db.commit()
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return ApprovalRequestOut.model_validate(req)


@router.post("/requests/{request_id}/cancel", response_model=ApprovalRequestOut)
async def cancel(
    request_id: str,
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ApprovalRequestOut:
    try:
        req = await cancel_request(db, requester=current_user, request_id=request_id)
        await db.commit()
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return ApprovalRequestOut.model_validate(req)


@router.post("/requests/{request_id}/execute", response_model=dict)
async def execute(
    request_id: str,
    current_user: Annotated[User, Depends(require_roles(["admin", "auditor"]))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    req = await get_request(db, request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")
    try:
        result = await execute_approved_request(db, req)
        await db.commit()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return result

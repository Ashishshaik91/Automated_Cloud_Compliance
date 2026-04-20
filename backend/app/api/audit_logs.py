"""
Audit Log API — read-only access to the audit trail.
Admin and Auditor roles can query + export logs. All other roles are denied.
"""

import csv
import io
from datetime import datetime
from typing import Annotated, Optional

import structlog
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import AuditorUser
from app.models.audit_log import AuditLog
from app.models.database import get_db
from app.schemas.audit_log import AuditLogResponse

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.get("", response_model=list[AuditLogResponse])
async def list_audit_logs(
    current_user: AuditorUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    action: Optional[str] = Query(None, description="Filter by action prefix, e.g. 'role'"),
    since: Optional[datetime] = Query(None, description="ISO datetime filter — events after this time"),
    until: Optional[datetime] = Query(None, description="ISO datetime filter — events before this time"),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
) -> list[AuditLogResponse]:
    """Return paginated audit logs. Auditor+ only."""
    q = select(AuditLog).order_by(AuditLog.timestamp.desc())
    if user_id:
        q = q.where(AuditLog.user_id == user_id)
    if action:
        q = q.where(AuditLog.action.startswith(action))
    if since:
        q = q.where(AuditLog.timestamp >= since)
    if until:
        q = q.where(AuditLog.timestamp <= until)
    q = q.limit(limit).offset(offset)

    result = await db.execute(q)
    return [AuditLogResponse.model_validate(r) for r in result.scalars().all()]


@router.get("/export")
async def export_audit_logs(
    current_user: AuditorUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    since: Optional[datetime] = Query(None),
    until: Optional[datetime] = Query(None),
) -> StreamingResponse:
    """Export audit logs as a CSV download. Auditor+ only."""
    q = select(AuditLog).order_by(AuditLog.timestamp.desc())
    if since:
        q = q.where(AuditLog.timestamp >= since)
    if until:
        q = q.where(AuditLog.timestamp <= until)

    result = await db.execute(q)
    logs = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "user_email", "action", "resource_type", "resource_id", "ip_address", "detail"])
    for log in logs:
        writer.writerow([
            log.id,
            log.timestamp.isoformat(),
            log.user_email,
            log.action,
            log.resource_type or "",
            log.resource_id or "",
            log.ip_address or "",
            str(log.detail or ""),
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_logs.csv"},
    )

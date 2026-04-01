"""
AuditLog model — immutable record of every state-mutating action in the system.

Every POST / PATCH / DELETE endpoint calls core.audit.log_event() to write here.
Viewer-role GET actions are not logged (too noisy, read-only).
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Who did it
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    user_email: Mapped[str] = mapped_column(String(255), nullable=False)

    # What they did — dot-namespaced, e.g. "user.create", "role.assign", "role.expire"
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    # What resource was affected
    resource_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Structured detail payload (before/after state, params, etc.)
    detail: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Network context
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)  # IPv6-safe

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    __table_args__ = (
        # Composite index for common query patterns: user timeline, action filter
        Index("ix_audit_user_time", "user_id", "timestamp"),
        Index("ix_audit_action_time", "action", "timestamp"),
    )

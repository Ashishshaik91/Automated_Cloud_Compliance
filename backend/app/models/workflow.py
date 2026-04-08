"""
Approval Workflow model — 4-eyes gate for high-risk platform actions.

State machine:
  PENDING → APPROVED → EXECUTED
  PENDING → REJECTED
  PENDING → CANCELLED  (by requester before review)
  PENDING → EXPIRED    (Celery beat sweeps every hour)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.database import Base


class ApprovalStatus:
    PENDING   = "pending"
    APPROVED  = "approved"
    REJECTED  = "rejected"
    CANCELLED = "cancelled"
    EXPIRED   = "expired"
    EXECUTED  = "executed"


class ApprovalRequest(Base):
    """
    A change-management request that requires explicit approval before execution.
    High-risk remediations and policy changes are gated here.
    """

    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)

    # What operation will be executed on approval
    action_type: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # "remediation", "policy_change", "account_delete", "mfa_bypass"
    action_payload: Mapped[Optional[dict]] = mapped_column(JSON)  # exact params for execution

    # Workflow state
    status: Mapped[str] = mapped_column(String(50), default=ApprovalStatus.PENDING, nullable=False, index=True)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)  # critical / high / medium

    # Scoping
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # People
    requester_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=False
    )
    approver_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Timestamps
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Outcome
    notes: Mapped[Optional[str]] = mapped_column(Text)          # approver reason / rejection note
    execution_result: Mapped[Optional[dict]] = mapped_column(JSON)

    # Relationships
    requester: Mapped["User"] = relationship(  # type: ignore[name-defined]
        "User", foreign_keys=[requester_id], lazy="select"
    )
    approver: Mapped[Optional["User"]] = relationship(  # type: ignore[name-defined]
        "User", foreign_keys=[approver_id], lazy="select"
    )

    @property
    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at

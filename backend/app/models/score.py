"""
SQLAlchemy models for the Compliance Score Engine.

Tables:
  score_snapshots     — daily org-level history for trending
  account_score_cache — latest per-account per-framework fast-read cache
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Optional

from sqlalchemy import (
    Date, DateTime, Float, ForeignKey, Integer, JSON, String, UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.database import Base


class ScoreSnapshot(Base):
    """Daily org-level compliance score snapshot for historical trending."""

    __tablename__ = "score_snapshots"
    __table_args__ = (
        UniqueConstraint("org_id", "snapshot_date", name="uq_score_snapshot_org_date"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    overall_score: Mapped[float] = mapped_column(Float, nullable=False)
    grade: Mapped[str] = mapped_column(String(1), nullable=False)          # A / B / C / D / F
    by_framework: Mapped[Optional[dict]] = mapped_column(JSON)             # {"pci_dss": 78.2, ...}
    account_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_fails: Mapped[int] = mapped_column(Integer, default=0)
    dspm_risk_avg: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class AccountScoreCache(Base):
    """
    Latest per-account, per-framework score — updated at end of every scan.
    Used by the dashboard for fast reads without recomputing from raw checks.
    """

    __tablename__ = "account_score_cache"
    __table_args__ = (
        UniqueConstraint("account_id", "framework", name="uq_account_score_cache_fw"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[int] = mapped_column(
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    framework: Mapped[str] = mapped_column(String(100), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    grade: Mapped[str] = mapped_column(String(1), nullable=False)
    critical_fails: Mapped[int] = mapped_column(Integer, default=0)
    high_fails: Mapped[int] = mapped_column(Integer, default=0)
    last_computed: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

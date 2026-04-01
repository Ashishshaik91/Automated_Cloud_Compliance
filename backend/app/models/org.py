"""
Organization and UserAccountRole models.

Organization  — groups of cloud accounts (supports parent/child hierarchy).
UserAccountRole — links a user to a specific cloud account with a role and optional expiry.
"""

import enum
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean, DateTime, Enum, ForeignKey,
    Integer, JSON, String, UniqueConstraint, select
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.database import Base


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    AUDITOR = "auditor"
    DEV = "dev"
    VIEWER = "viewer"


class Organization(Base):
    """A logical grouping of cloud accounts. Supports nested hierarchy via parent_org_id."""

    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    parent_org_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    parent: Mapped[Optional["Organization"]] = relationship(
        "Organization", remote_side="Organization.id", back_populates="children"
    )
    children: Mapped[list["Organization"]] = relationship(
        "Organization", back_populates="parent"
    )


class UserAccountRole(Base):
    """
    Associates a user with a cloud account and a role.

    expires_at=None  →  permanent grant
    expires_at=<dt>  →  temporary grant (auto-expires; Celery task cleans up hourly)
    """

    __tablename__ = "user_account_roles"
    __table_args__ = (
        UniqueConstraint("user_id", "cloud_account_id", name="uq_user_account"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    cloud_account_id: Mapped[int] = mapped_column(
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(
        Enum(UserRole, name="user_role_enum"), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Time-limited access — null means permanent
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Audit trail fields
    granted_by: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    @property
    def is_expired(self) -> bool:
        """Returns True if this role grant has passed its expiry time."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    @classmethod
    async def get_for_user_and_account(
        cls, db: AsyncSession, user_id: int, account_id: int
    ) -> Optional["UserAccountRole"]:
        result = await db.execute(
            select(cls).where(
                cls.user_id == user_id,
                cls.cloud_account_id == account_id,
                cls.is_active == True,
            )
        )
        return result.scalar_one_or_none()

    @classmethod
    async def get_all_for_user(
        cls, db: AsyncSession, user_id: int
    ) -> list["UserAccountRole"]:
        result = await db.execute(
            select(cls).where(cls.user_id == user_id).order_by(cls.granted_at.desc())
        )
        return list(result.scalars().all())

"""
User SQLAlchemy model.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from app.auth.jwt import hash_password
from app.models.database import Base
from app.schemas.auth import UserCreate


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="analyst", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    @classmethod
    async def get_by_id(cls, db: AsyncSession, user_id: int) -> Optional["User"]:
        result = await db.execute(select(cls).where(cls.id == user_id))
        return result.scalar_one_or_none()

    @classmethod
    async def get_by_email(cls, db: AsyncSession, email: str) -> Optional["User"]:
        result = await db.execute(
            select(cls).where(cls.email == email.lower().strip())
        )
        return result.scalar_one_or_none()

    @classmethod
    async def create(cls, db: AsyncSession, user_in: "UserCreate") -> "User":
        user = cls(
            email=user_in.email.lower().strip(),
            full_name=user_in.full_name,
            hashed_password=hash_password(user_in.password),
            role="analyst",
        )
        db.add(user)
        await db.flush()
        return user

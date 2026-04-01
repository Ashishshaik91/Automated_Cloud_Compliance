"""
Database seeder — creates default users for all 4 roles on first startup.
Credentials are read from environment variables with safe local-dev fallbacks.

Set these in your .env file to override the defaults:
  SEED_ADMIN_EMAIL / SEED_ADMIN_PASSWORD / SEED_ADMIN_NAME
  SEED_AUDITOR_EMAIL / SEED_AUDITOR_PASSWORD / SEED_AUDITOR_NAME
  SEED_DEV_EMAIL / SEED_DEV_PASSWORD / SEED_DEV_NAME
  SEED_VIEWER_EMAIL / SEED_VIEWER_PASSWORD / SEED_VIEWER_NAME
"""

import os

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import hash_password
from app.models.user import User

logger = structlog.get_logger(__name__)


def _seed_users():
    return [
        {
            "email":     os.getenv("SEED_ADMIN_EMAIL",    "admin@compliance.local"),
            "full_name": os.getenv("SEED_ADMIN_NAME",     "System Admin"),
            "password":  os.getenv("SEED_ADMIN_PASSWORD", "Admin@Secure2024!"),
            "role": "admin",
        },
        {
            "email":     os.getenv("SEED_AUDITOR_EMAIL",    "auditor@compliance.local"),
            "full_name": os.getenv("SEED_AUDITOR_NAME",     "System Auditor"),
            "password":  os.getenv("SEED_AUDITOR_PASSWORD", "Audit@Secure2024!"),
            "role": "auditor",
        },
        {
            "email":     os.getenv("SEED_DEV_EMAIL",    "dev@compliance.local"),
            "full_name": os.getenv("SEED_DEV_NAME",     "System Dev"),
            "password":  os.getenv("SEED_DEV_PASSWORD", "Dev@Secure2024!"),
            "role": "dev",
        },
        {
            "email":     os.getenv("SEED_VIEWER_EMAIL",    "viewer@compliance.local"),
            "full_name": os.getenv("SEED_VIEWER_NAME",     "System Viewer"),
            "password":  os.getenv("SEED_VIEWER_PASSWORD", "Viewer@Secure2024!"),
            "role": "viewer",
        },
    ]


async def seed_default_users(db: AsyncSession) -> None:
    """Idempotent: only seeds users that don't already exist."""
    for data in _seed_users():
        existing = await User.get_by_email(db, data["email"])
        if existing:
            continue

        user = User(
            email=data["email"],
            full_name=data["full_name"],
            hashed_password=hash_password(data["password"]),
            role=data["role"],
            is_active=True,
        )
        db.add(user)
        logger.info("Seeded default user", email=data["email"], role=data["role"])

    await db.flush()

"""Celery task — hourly sweep to expire stale approval requests."""
from __future__ import annotations

import asyncio

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.celery_app import celery_app
from app.core.workflow_engine import expire_stale_requests
from app.models.database import AsyncSessionLocal

logger = structlog.get_logger(__name__)


@celery_app.task(name="tasks.expire_stale_approvals", bind=True, max_retries=3)
def expire_stale_approvals_task(self: object) -> dict:
    """Mark all PENDING approval requests past their expires_at as EXPIRED."""

    async def _run() -> int:
        async with AsyncSessionLocal() as db:
            count = await expire_stale_requests(db)
            await db.commit()
            return count

    count = asyncio.get_event_loop().run_until_complete(_run())
    logger.info("Expiry sweep done", expired=count)
    return {"expired": count}

"""Celery task — daily per-org compliance score snapshot."""
from __future__ import annotations

import asyncio

import structlog
from celery import shared_task
from sqlalchemy import select

from app.core.celery_app import celery_app
from app.core.score_engine import take_daily_snapshot
from app.models.database import AsyncSessionLocal
from app.models.org import Organization

logger = structlog.get_logger(__name__)


@celery_app.task(name="tasks.take_score_snapshot", bind=True, max_retries=3)
def take_score_snapshot_task(self: object) -> dict:
    """Compute and store a daily score snapshot for every active org."""

    async def _run() -> dict:
        counts = {"snapshots": 0, "errors": 0}
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Organization))
            orgs = result.scalars().all()
            for org in orgs:
                try:
                    snapshot = await take_daily_snapshot(db, org.id)
                    if snapshot:
                        await db.commit()
                        counts["snapshots"] += 1
                except Exception as e:
                    logger.error("Score snapshot failed", org_id=org.id, error=str(e))
                    counts["errors"] += 1
        return counts

    counts = asyncio.get_event_loop().run_until_complete(_run())
    logger.info("Score snapshots complete", **counts)
    return counts

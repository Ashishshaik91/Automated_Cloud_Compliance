"""
Data Ingestion Pipeline.
Ingests logs, metrics, and security events from cloud sources.
Uses Redis Streams for scalable, reliable event processing.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
import structlog

from app.config import get_settings

settings = get_settings()
logger = structlog.get_logger(__name__)

STREAM_KEY = "compliance:events"
CONSUMER_GROUP = "compliance-processor"


class IngestionPipeline:
    """
    Scalable data ingestion pipeline using Redis Streams.
    Ingests CloudTrail events, Azure Monitor logs, GCP audit logs.
    """

    def __init__(self) -> None:
        self._redis: aioredis.Redis | None = None

    @property
    async def redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = await aioredis.from_url(
                settings.redis_url,
                decode_responses=True,
            )
        return self._redis

    async def ingest_event(self, event: dict[str, Any]) -> str:
        """
        Publish a single event to the Redis stream.
        Returns the stream entry ID.
        """
        client = await self.redis
        event_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": event.get("source", "unknown"),
            "event_type": event.get("event_type", "unknown"),
            "payload": json.dumps(event),
        }
        entry_id = await client.xadd(STREAM_KEY, event_data)
        logger.debug("Event ingested", event_id=entry_id, source=event_data["source"])
        return entry_id

    async def ingest_batch(self, events: list[dict[str, Any]]) -> list[str]:
        """Bulk ingest multiple events."""
        tasks = [self.ingest_event(e) for e in events]
        return await asyncio.gather(*tasks)

    async def process_events(self, batch_size: int = 100) -> None:
        """
        Read events from Redis stream and process them.
        Creates consumer group if not exists.
        """
        client = await self.redis
        # Create consumer group
        try:
            await client.xgroup_create(STREAM_KEY, CONSUMER_GROUP, id="0", mkstream=True)
        except Exception:
            pass  # Group already exists

        while True:
            messages = await client.xreadgroup(
                CONSUMER_GROUP,
                "worker-1",
                {STREAM_KEY: ">"},
                count=batch_size,
                block=5000,  # 5 seconds
            )
            if messages:
                for _, entries in messages:
                    for entry_id, data in entries:
                        await self._process_entry(entry_id, data)
                        await client.xack(STREAM_KEY, CONSUMER_GROUP, entry_id)

    async def _process_entry(self, entry_id: str, data: dict[str, str]) -> None:
        """Process a single ingested event entry."""
        try:
            payload = json.loads(data.get("payload", "{}"))
            event_type = data.get("event_type", "")
            source = data.get("source", "")

            logger.info(
                "Processing event",
                entry_id=entry_id,
                event_type=event_type,
                source=source,
            )

            # Route to appropriate processor based on source
            if source == "cloudtrail":
                await self._process_cloudtrail_event(payload)
            elif source == "azure_monitor":
                await self._process_azure_event(payload)
            elif source == "gcp_audit":
                await self._process_gcp_event(payload)

        except Exception as e:
            logger.error("Event processing failed", entry_id=entry_id, error=str(e))

    async def _process_cloudtrail_event(self, event: dict[str, Any]) -> None:
        """Process AWS CloudTrail events for policy violations."""
        event_name = event.get("eventName", "")
        # Flag suspicious API calls
        sensitive_actions = {
            "DeleteBucket", "PutBucketPublicAccessBlock", "DeleteTrail",
            "StopLogging", "CreateUser", "AttachUserPolicy",
        }
        if event_name in sensitive_actions:
            logger.warning(
                "Sensitive CloudTrail event detected",
                event_name=event_name,
                user=event.get("userIdentity", {}).get("arn"),
            )

    async def _process_azure_event(self, event: dict[str, Any]) -> None:
        """Process Azure Monitor events."""
        operation = event.get("operationName", "")
        logger.debug("Azure event processed", operation=operation)

    async def _process_gcp_event(self, event: dict[str, Any]) -> None:
        """Process GCP Audit Log events."""
        method = event.get("methodName", "")
        logger.debug("GCP event processed", method=method)

    async def close(self) -> None:
        if self._redis:
            await self._redis.aclose()

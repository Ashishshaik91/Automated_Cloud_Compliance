"""
Celery application configuration.
Handles async task scheduling for compliance scans.
"""

from celery import Celery
from celery.schedules import crontab

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "compliance_platform",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.core.scanner", "app.core.ingestion", "app.core.threat_intel_task"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,  # Fair task distribution
    task_routes={
        "tasks.run_scheduled_scan": {"queue": "scans"},
        "tasks.ingest_events": {"queue": "ingestion"},
        "tasks.run_scheduled_enrichment": {"queue": "scans"},
    },
    beat_schedule={
        # Run all scans every 5 minutes (configurable)
        "scheduled-compliance-scan": {
            "task": "tasks.run_scheduled_scan",
            "schedule": settings.scan_interval_seconds,
            "args": (1, "all"),  # account_id=1, framework=all
        },
        # Run threat intel enrichment every 6 hours (21600 seconds)
        "scheduled-threat-intel-enrichment": {
            "task": "tasks.run_scheduled_enrichment",
            "schedule": 21600.0,
        },
    },
)

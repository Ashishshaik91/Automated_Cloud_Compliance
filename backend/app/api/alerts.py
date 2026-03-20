"""
Alerting API routes — list alerts, acknowledge, and send notifications.
"""

from datetime import datetime, timezone
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import CurrentUser
from app.models.database import get_db
from app.schemas.compliance import AlertResponse

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.get("/", response_model=list[AlertResponse])
async def list_alerts(
    _: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    acknowledged: bool | None = None,
    limit: int = 50,
) -> list[AlertResponse]:
    """List compliance alerts."""
    # Alert model would be added in next iteration
    # Returning mock structure showing the interface
    return []


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Acknowledge a compliance alert."""
    logger.info("Alert acknowledged", alert_id=alert_id, user_id=current_user.id)
    return {"status": "acknowledged", "alert_id": alert_id}


async def send_slack_alert(webhook_url: str, message: str, severity: str) -> bool:
    """Send an alert to Slack webhook."""
    import httpx
    color_map = {
        "critical": "#dc2626",
        "high": "#f59e0b",
        "medium": "#3b82f6",
        "low": "#6b7280",
    }
    payload = {
        "attachments": [{
            "color": color_map.get(severity, "#6b7280"),
            "title": f"🚨 Compliance Alert — {severity.upper()}",
            "text": message,
            "footer": "Cloud Compliance Platform",
            "ts": int(datetime.now(timezone.utc).timestamp()),
        }]
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(webhook_url, json=payload)
            return resp.status_code == 200
    except Exception as e:
        logger.error("Slack alert failed", error=str(e))
        return False


async def send_email_alert(
    to_email: str, subject: str, body: str,
    smtp_host: str, smtp_port: int, smtp_user: str, smtp_password: str, from_email: str,
) -> bool:
    """Send an email alert via SMTP."""
    import smtplib
    from email.mime.text import MIMEText
    try:
        msg = MIMEText(body, "html")
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = to_email
        with smtplib.SMTP(smtp_host, smtp_port) as smtp:
            smtp.starttls()
            smtp.login(smtp_user, smtp_password)
            smtp.send_message(msg)
        return True
    except Exception as e:
        logger.error("Email alert failed", error=str(e))
        return False

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
from app.config import get_settings
from pydantic import BaseModel

router = APIRouter()
logger = structlog.get_logger(__name__)

class TestAlertRequest(BaseModel):
    email: str


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

@router.post("/test-email")
async def send_test_alert_email(
    req: TestAlertRequest,
    current_user: CurrentUser,
) -> dict:
    """Trigger a test email using SMTP config."""
    settings = get_settings()
    if not settings.smtp_host:
        raise HTTPException(status_code=400, detail="SMTP is not configured in environment variables.")
        
    smtp_pass = settings.smtp_password.get_secret_value() if settings.smtp_password else ""
    success = await send_email_alert(
        to_email=req.email,
        subject="Cloud Compliance Platform — Test Alert",
        body="<h2>Configuration Successful!</h2><p>Your SMTP environment variables are working correctly.</p><p>You will now receive compliance alerts at this address.</p>",
        smtp_host=settings.smtp_host,
        smtp_port=settings.smtp_port,
        smtp_user=settings.smtp_user,
        smtp_password=smtp_pass,
        from_email=settings.smtp_from_email,
    )
    if not success:
        raise HTTPException(status_code=500, detail="Failed to send test email. Check backend logs or SMTP credentials.")
    return {"status": "success", "message": f"Test email sent to {req.email}"}


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

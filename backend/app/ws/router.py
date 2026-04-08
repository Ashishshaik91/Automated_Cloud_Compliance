"""
WebSocket router — JWT-authenticated live feed endpoint.

Clients connect with:
  ws://host/api/v1/ws/live?token=<access_token>

Events streamed:
  scan.completed      violation.detected   score.updated
  approval.pending    alert.fired          remediation.result
"""
from __future__ import annotations

import structlog
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import decode_token
from app.models.database import AsyncSessionLocal
from app.models.user import User
from app.ws.connection_manager import connect, disconnect

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.websocket("/live")
async def live_feed(
    websocket: WebSocket,
    token: str = Query(..., description="JWT access token (query param — headers not supported in WS)"),
) -> None:
    """
    Live compliance event feed.
    Authenticates via JWT query param, then streams org-scoped events.
    """
    # Authenticate
    try:
        payload = decode_token(token)
        if payload.get("type") not in ("access",):
            await websocket.close(code=4001, reason="Invalid token type")
            return
        user_id = int(payload["sub"])
        org_id = payload.get("org_id")
    except Exception:
        await websocket.close(code=4001, reason="Unauthorized")
        return

    # Load user for org scope
    async with AsyncSessionLocal() as db:
        user = await User.get_by_id(db, user_id)

    if not user or not user.is_active:
        await websocket.close(code=4003, reason="Forbidden")
        return

    # Resolve org_id: prefer JWT claim (faster), fall back to DB
    resolved_org = org_id or user.organization_id
    if resolved_org is None:
        await websocket.close(code=4003, reason="No org scope")
        return

    await connect(websocket, resolved_org)
    logger.info("WS live feed connected", user_id=user_id, org_id=resolved_org)

    try:
        # Keep the connection alive — client can send ping frames; we echo them
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        await disconnect(websocket, resolved_org)
        logger.info("WS live feed disconnected", user_id=user_id, org_id=resolved_org)

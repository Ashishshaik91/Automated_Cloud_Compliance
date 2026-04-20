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
from app.core.redis import get_redis, get_redis_pool
from app.ws.connection_manager import connect, disconnect
import redis.asyncio as aioredis

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.websocket("/live")
async def live_feed(
    websocket: WebSocket,
    ticket: str = Query(..., description="Short-lived WebSocket ticket"),
) -> None:
    """
    Live compliance event feed.
    Authenticates via one-time ticket, then streams role-scoped events.
    """
    # 1. Validate Ticket via Redis
    # We can't easily use Depends(get_redis) in a websocket, we'll manually get it or use depends
    # Wait, FastAPI DOES support Depends in websockets! But we can just use the AsyncSessionLocal block
    from app.core.redis import get_redis_pool
    client = aioredis.Redis(connection_pool=get_redis_pool())
    
    user_id_str = await client.getdel(f"ws_ticket:{ticket}")
    if not user_id_str:
        await websocket.close(code=1008, reason="Invalid or expired ticket")
        return
        
    user_id = int(user_id_str)

    # 2. Load user for org scope and role
    async with AsyncSessionLocal() as db:
        user = await User.get_by_id(db, user_id)

    if not user or not user.is_active:
        await websocket.close(code=1008, reason="Forbidden")
        return

    # 3. Resolve org_id
    resolved_org = user.organization_id
    if resolved_org is None:
        await websocket.close(code=1008, reason="No org scope")
        return

    # 4. Role-scoped room name: "org:{org_id}:role:{role}"
    # But wait, connection_manager is designed for just org_id currently.
    # Let's pass the room name to connection_manager instead of just org_id.
    # We will modify connection_manager next to support room names.
    room_name = f"org:{resolved_org}:role:{user.role}"
    await connect(websocket, room_name)
    logger.info("WS live feed connected", user_id=user_id, room=room_name)

    try:
        # Keep the connection alive — client can send ping frames; we echo them
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        await disconnect(websocket, room_name)
        logger.info("WS live feed disconnected", user_id=user_id, room=room_name)

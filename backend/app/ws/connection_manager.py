"""
WebSocket Connection Manager + Redis pub/sub listener.

Architecture:
  - Each role in each org has its own Redis channel: "compliance:live:org:{org_id}:role:{role}"
  - Any backend worker publishes to that channel via publisher.py
  - The listener task (started in lifespan) reads all matching channels
    and fans out to all connected WS clients scoped to that room
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog
from fastapi import WebSocket

logger = structlog.get_logger(__name__)

# room_name → set of connected WebSocket objects
_connections: dict[str, set[WebSocket]] = {}
_lock = asyncio.Lock()


async def connect(websocket: WebSocket, room_name: str) -> None:
    """Register a new WebSocket connection for a room."""
    await websocket.accept()
    async with _lock:
        _connections.setdefault(room_name, set()).add(websocket)
    logger.info("WS client connected", room=room_name, total=len(_connections.get(room_name, set())))


async def disconnect(websocket: WebSocket, room_name: str) -> None:
    """Remove a WebSocket connection."""
    async with _lock:
        room_conns = _connections.get(room_name, set())
        room_conns.discard(websocket)
        if not room_conns:
            _connections.pop(room_name, None)
    logger.info("WS client disconnected", room=room_name)


async def broadcast_to_room(room_name: str, event: dict[str, Any]) -> None:
    """Fan-out a JSON event to all WS clients in the given room."""
    payload = json.dumps(event)
    dead: list[WebSocket] = []
    for ws in list(_connections.get(room_name, set())):
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    # Clean up dead connections
    async with _lock:
        for ws in dead:
            _connections.get(room_name, set()).discard(ws)


async def start_redis_listener(redis_url: str) -> None:
    """
    Background task started in app lifespan.
    Subscribes to 'compliance:live:*' channels and calls broadcast_to_org
    whenever a message is published.
    """
    import redis.asyncio as aioredis

    while True:  # reconnect loop
        try:
            client = aioredis.from_url(redis_url, decode_responses=True)
            pubsub = client.pubsub()
            await pubsub.psubscribe("compliance:live:*")
            logger.info("Redis WS listener subscribed to compliance:live:*")

            async for message in pubsub.listen():
                if message["type"] != "pmessage":
                    continue
                try:
                    # Channel format: "compliance:live:{room_name}"
                    channel: str = message["channel"]
                    room_name = channel.replace("compliance:live:", "")
                    data = json.loads(message["data"])
                    await broadcast_to_room(room_name, data)
                except Exception as e:
                    logger.warning("WS listener parse error", error=str(e))

        except Exception as e:
            logger.error("Redis WS listener crashed, reconnecting in 5s", error=str(e))
            await asyncio.sleep(5)

import redis.asyncio as aioredis
from typing import AsyncGenerator
from app.config import get_settings

settings = get_settings()

_redis_pool = None

def get_redis_pool() -> aioredis.ConnectionPool:
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = aioredis.ConnectionPool.from_url(
            settings.redis_url, 
            decode_responses=True,
            password=settings.redis_password.get_secret_value() if settings.redis_password else None
        )
    return _redis_pool

async def get_redis() -> AsyncGenerator[aioredis.Redis, None]:
    """Dependency for getting a Redis client connection."""
    client = aioredis.Redis(connection_pool=get_redis_pool())
    try:
        yield client
    finally:
        await client.aclose()

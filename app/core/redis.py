import redis.asyncio as redis
from app.core.config import REDIS_URL

redis_client = None

async def init_redis():
    global redis_client
    redis_client = await redis.from_url(REDIS_URL, decode_responses=True)
    return redis_client


async def close_redis():
    global redis_client
    if redis_client:
        await redis_client.close()


def get_redis():
    return redis_client


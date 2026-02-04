from redis import Redis
from app.settings import settings


def get_redis() -> Redis:
    return Redis.from_url(settings.REDIS_URL, decode_responses=True)

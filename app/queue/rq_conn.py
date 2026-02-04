from redis import Redis
from rq import Queue
from app.settings import settings


def get_queue() -> Queue:
    conn = Redis.from_url(settings.REDIS_URL)
    return Queue(settings.RQ_QUEUE_NAME, connection=conn)

from contextlib import contextmanager
import time
from app.store.redis_conn import get_redis

@contextmanager
def session_lock(session_id: str, ttl_ms: int = 5000):
    """
    Distributed lock to ensure single-writer per session.
    """
    r = get_redis()
    key = f"lock:session:{session_id}"
    token = str(time.time())
    acquired = r.set(key, token, px=ttl_ms, nx=True)
    
    try:
        if not acquired:
            # Fast-fail or spin? Prompt implies "guarding finalize", usually fail or wait.
            # For an API, blocking a bit is okay, or fail with 429.
            # Let's try a short spin.
            for _ in range(5):
                time.sleep(0.1)
                if r.set(key, token, px=ttl_ms, nx=True):
                    acquired = True
                    break
            
            if not acquired:
                raise RuntimeError(f"Could not acquire lock for session {session_id}")
        
        yield
    finally:
        if acquired:
            # Release only if we own it
            script = """
            if redis.call("get", KEYS[1]) == ARGV[1] then
                return redis.call("del", KEYS[1])
            else
                return 0
            end
            """
            try:
                r.eval(script, 1, key, token)
            except Exception:
                pass

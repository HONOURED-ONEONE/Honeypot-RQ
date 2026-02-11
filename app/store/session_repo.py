import json
import time
from app.store.redis_conn import get_redis
from app.store.models import SessionState, Intelligence

PREFIX = "session:"


def _key(session_id: str) -> str:
    return f"{PREFIX}{session_id}"


def _json_safe(obj):
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_safe(v) for v in obj]
    return obj


def load_session(session_id: str) -> SessionState:
    r = get_redis()
    raw = r.get(_key(session_id))
    if not raw:
        s = SessionState(sessionId=session_id)
        s.lastUpdatedAtEpoch = int(time.time())
        return s

    data = json.loads(raw)

    # Rehydrate Intelligence object
    intel = Intelligence(**data.get("extractedIntelligence", {}))
    data["extractedIntelligence"] = intel

    return SessionState(**data)


def save_session(session: SessionState) -> None:
    r = get_redis()
    session.lastUpdatedAtEpoch = int(time.time())

    data = session.__dict__.copy()
    data["extractedIntelligence"] = session.extractedIntelligence.__dict__

    safe_data = _json_safe(data)
    r.set(_key(session.sessionId), json.dumps(safe_data))

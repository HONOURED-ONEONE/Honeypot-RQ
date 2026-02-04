import json
import time
from app.store.redis_conn import get_redis
from app.store.models import SessionState, Intelligence

PREFIX = "session:"


def _key(session_id: str) -> str:
    return f"{PREFIX}{session_id}"


def load_session(session_id: str) -> SessionState:
    r = get_redis()
    raw = r.get(_key(session_id))
    if not raw:
        s = SessionState(sessionId=session_id)
        s.lastUpdatedAtEpoch = int(time.time())
        return s

    data = json.loads(raw)
    intel = Intelligence(**data.get("extractedIntelligence", {}))
    s = SessionState(**{**data, "extractedIntelligence": intel})
    return s


def save_session(session: SessionState) -> None:
    r = get_redis()
    session.lastUpdatedAtEpoch = int(time.time())
    data = session.__dict__.copy()
    data["extractedIntelligence"] = session.extractedIntelligence.__dict__
    r.set(_key(session.sessionId), json.dumps(data))

"""
GuardedConfigWriter: allow runtime rule changes DURING a session,
but ensure they reset for other sessions.

Principles:
- Session-scoped overlays are stored in Redis under session-specific keys.
- Orchestrator calls begin_session_overlay(sessionId) before controller runs,
  and end_session_overlay() immediately after, restoring base state.
- This prevents cross-session leakage and keeps behavior deterministic.
"""
from typing import Optional, Dict, Any
import json
import threading
from app.store.redis_conn import get_redis
from app.settings import settings
from app.intel.artifact_registry import artifact_registry

_TLS = threading.local()

INTENT_MAP_SESSION_KEY   = "registry:intent_map:session:{sid}"
DYNAMIC_ARTS_SESSION_KEY = "registry:dynamic:session:{sid}"

def set_session_intent_map(session_id: str, data: Dict[str, Any], ttl_sec: int = 300) -> None:
    """Write an intent-map override for this session only."""
    r = get_redis()
    r.set(INTENT_MAP_SESSION_KEY.format(sid=session_id), json.dumps(data), ex=int(ttl_sec))

def set_session_dynamic_artifacts(session_id: str, data: Dict[str, Any], ttl_sec: int = 300) -> None:
    """Write dynamic artifacts override for this session only."""
    r = get_redis()
    r.set(DYNAMIC_ARTS_SESSION_KEY.format(sid=session_id), json.dumps(data), ex=int(ttl_sec))

def _load_session_overrides(session_id: str) -> Dict[str, Any]:
    """Fetch session-scoped overrides (intent-map & dynamic artifacts)."""
    out: Dict[str, Any] = {"intent_map": None, "dynamic": None}
    try:
        r = get_redis()
        im_raw = r.get(INTENT_MAP_SESSION_KEY.format(sid=session_id))
        if im_raw:
            im = json.loads(im_raw)
            if isinstance(im, dict):
                out["intent_map"] = {k: {"intent": v.get("intent"), "instruction": v.get("instruction")} for k, v in im.items() if isinstance(v, dict)}
    except Exception:
        pass
    try:
        r = get_redis()
        dyn_raw = r.get(DYNAMIC_ARTS_SESSION_KEY.format(sid=session_id))
        if dyn_raw:
            dyn = json.loads(dyn_raw)
            if isinstance(dyn, dict):
                out["dynamic"] = dyn
    except Exception:
        pass
    return out

def begin_session_overlay(session_id: str) -> None:
    """
    Apply session-specific overlays by merging them into the in-memory registry
    for this thread only. Save originals in TLS to be restored by end_session_overlay.
    """
    ov = _load_session_overrides(session_id)
    # Save originals
    _TLS.saved_intent_map = getattr(artifact_registry, "intent_map", {}).copy()
    _TLS.session_overlay_applied = False

    # Merge intent-map overlay
    try:
        if isinstance(ov.get("intent_map"), dict) and ov["intent_map"]:
            merged = _TLS.saved_intent_map.copy()
            merged.update(ov["intent_map"])
            artifact_registry.intent_map = merged
            _TLS.session_overlay_applied = True
    except Exception:
        # keep originals
        pass

    # (Optional) dynamic artifacts are stored in redis and consumed by extractor via _maybe_refresh_overrides.
    # We don't mutate registry.artifacts here to avoid long-lived cross-session effects.
    # If desired, extractor can fetch session_key-specific patterns on demand.

def end_session_overlay() -> None:
    """Restore original registry maps after controller/respond cycle."""
    try:
        if getattr(_TLS, "session_overlay_applied", False):
            artifact_registry.intent_map = getattr(_TLS, "saved_intent_map", {}) or {}
    except Exception:
        pass
    finally:
        for k in ("session_overlay_applied", "saved_intent_map"):
            if hasattr(_TLS, k):
                try:
                    delattr(_TLS, k)
                except Exception:
                    pass

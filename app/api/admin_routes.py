from fastapi import APIRouter, Depends, HTTPException, Header
from app.settings import settings
from app.store.session_repo import load_session
from app.store.redis_conn import get_redis

router = APIRouter(prefix="/admin", tags=["admin"])

def require_admin(x_admin_key: str = Header(default="", alias="x-admin-key")):
    if not settings.ADMIN_RBAC_ENABLED:
        return
    # Secure default: if enabled but no key configured, reject all.
    if not settings.ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Admin access disabled (no key configured)")
    if x_admin_key != settings.ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid admin key")

@router.get("/session/{session_id}/timeline")
def get_session_timeline(session_id: str, _=Depends(require_admin)):
    """Ordered event stream for the session."""
    s = load_session(session_id)
    events = []
    
    # Conversation events
    for m in s.conversation or []:
        events.append({
            "timestamp": m.get("timestamp"),
            "type": "message",
            "sender": m.get("sender"),
            "content": m.get("text")
        })
        
    # Postscript events (latched)
    for p in s.postscript or []:
         events.append({
            "timestamp": p.get("timestamp"),
            "type": "postscript_message",
            "sender": p.get("sender"),
            "content": p.get("text"),
            "ignored": True
         })
    
    # Finalization event
    if s.finalizedAt:
        events.append({
            "timestamp": s.finalizedAt,
            "type": "lifecycle_finalized",
            "reportId": s.reportId,
            "reason": (s.agentNotes or "").split("|")[-1].strip() if "finalize_reason=" in (s.agentNotes or "") else "unknown"
        })
        
    # Sort by timestamp
    return sorted(events, key=lambda x: int(x.get("timestamp", 0) or 0))

@router.get("/callbacks")
def get_callbacks(session_id: str, _=Depends(require_admin)):
    """View the idempotency ledger for a session."""
    s = load_session(session_id)
    return {
        "sessionId": session_id,
        "callbackStatus": s.callbackStatus,
        "outboxLedger": s.outboxEntry or {},
        "finalReportPreview": s.finalReport
    }

@router.get("/slo")
def get_slo(_=Depends(require_admin)):
    """
    Observability snapshot.
    Note: In a real production system, this would query Prometheus/Datadog.
    Here we return a stub or simple Redis counters if implemented.
    """
    return {
        "message": "SLO metrics require external TSDB.",
        "config": {
             "finalize_min_turns": settings.FINALIZE_MIN_TURNS,
             "finalize_timeout": settings.FINALIZE_INACTIVITY_SECONDS
        }
    }

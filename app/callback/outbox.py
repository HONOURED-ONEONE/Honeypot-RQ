import time
import json
import random
from typing import List, Dict, Any, Optional

from app.settings import settings
import app.store.session_repo as session_repo
from app.observability.logging import log
from app.store.redis_conn import get_redis
import app.callback.client as callback_client
import app.observability.metrics as metrics

def _now_ms() -> int:
    return int(time.time() * 1000)

def _calc_backoff(attempt: int) -> int:
    """Exponential backoff with jitter."""
    base = int(getattr(settings, "CALLBACK_BASE_DELAY_MS", 1000) or 1000)
    max_delay = int(getattr(settings, "CALLBACK_MAX_DELAY_MS", 3600000) or 3600000)
    delay = base * (2 ** (attempt - 1))
    jitter = delay * 0.1 * random.uniform(-1, 1)
    return min(max_delay, int(delay + jitter))

def enqueue_outbox_entry(session_id: str) -> str:
    """
    Ensures the session has an outbox entry initialized.
    Currently persistence is handled via session state, so this acts as a check/init.
    """
    # In this architecture, orchestrator handles the initial persist.
    # This function is a placeholder for strict Outbox separation if we move to a dedicated table later.
    return session_id

def process_outbox_entry(session_id: str) -> bool:
    """
    Idempotent processor for the callback outbox.
    Returns True if delivery succeeded or terminal failure reached.
    Returns False if retry is scheduled.
    """
    if not settings.ENABLE_OUTBOX:
        log(event="outbox_disabled", sessionId=session_id)
        return True

    session = session_repo.load_session(session_id)
    
    if not session.finalReport:
        log(event="outbox_empty_report", sessionId=session_id)
        return True

    ledger = session.outboxEntry or {
        "attempts": 0,
        "history": [],
        "status": "pending",
        "nextAttemptAt": 0
    }
    
    if ledger.get("status") in ("delivered", "failed:terminal", "failed:dlq"):
        return True

    if _now_ms() < int(ledger.get("nextAttemptAt", 0) or 0):
        return False

    max_attempts = int(getattr(settings, "CALLBACK_MAX_ATTEMPTS", 12) or 12)
    if int(ledger.get("attempts", 0)) >= max_attempts:
        ledger["status"] = "failed:dlq"
        session.outboxEntry = ledger
        session_repo.save_session(session)
        try:
            r = get_redis()
            dlq_payload = json.dumps({
                "sessionId": session_id,
                "finalReport": session.finalReport,
                "ledger": ledger,
                "deadAt": _now_ms()
            })
            r.lpush("callback:dlq", dlq_payload)
        except Exception:
            pass
        log(event="callback_dlq_moved", sessionId=session_id, attempts=ledger["attempts"])
        return True

    attempt_idx = int(ledger.get("attempts", 0)) + 1
    
    headers = {
        "Idempotency-Key": str(session.reportId),
        "X-Report-Version": str(getattr(settings, "CALLBACK_PAYLOAD_VERSION", "1.1")),
        "Content-Type": "application/json"
    }

    start_ts = _now_ms()
    
    metrics.increment_callback_attempt()

    # Use Isolated Delivery Client
    success, status_code, error_msg = callback_client.send_final_result_http(
        session.finalReport, 
        headers, 
        timeout=float(settings.CALLBACK_TIMEOUT_SEC)
    )

    duration = _now_ms() - start_ts

    if success:
        metrics.increment_callback_delivered()
        metrics.record_callback_latency(duration)
    else:
        metrics.record_failed_callback(session_id)

    record = {
        "attempt": attempt_idx,
        "ts": start_ts,
        "duration": duration,
        "code": status_code,
        "error": error_msg,
        "success": success
    }
    ledger.setdefault("history", []).append(record)
    ledger["attempts"] = attempt_idx
    
    if success:
        ledger["status"] = "delivered"
        ledger["nextAttemptAt"] = 0
        session.callbackStatus = "sent"
        log(event="callback_delivered", sessionId=session_id, attempt=attempt_idx)
    else:
        backoff = _calc_backoff(attempt_idx)
        ledger["nextAttemptAt"] = _now_ms() + backoff
        ledger["status"] = "pending"
        
        # Terminal checks for 4xx (except 429)
        if 400 <= status_code < 500 and status_code != 429:
             ledger["status"] = "failed:terminal"
             log(event="callback_terminal_error", sessionId=session_id, code=status_code)
             success = True 
        else:
             log(event="callback_retry_scheduled", sessionId=session_id, attempt=attempt_idx, backoffMs=backoff)
             success = False 
    
    session.outboxEntry = ledger
    session_repo.save_session(session)
    return success

def drain_outbox(limit: int = 100) -> List[Dict]:
    """
    Placeholder for background sweeper that might scan Redis/DB for pending items.
    """
    return []

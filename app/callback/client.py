import time
from app.settings import settings
from app.store.session_repo import load_session, save_session
from app.callback.outbox import process_outbox_entry
from app.observability.logging import log
from app.queue.rq_conn import get_queue


def send_final_result(session_id: str):
    """
    Worker entry point: processes the outbox entry for the session.
    Manages retries via RQ rescheduling or sleep.
    """
    if not settings.GUVI_CALLBACK_URL:
        # If no URL, we can't send. Mark terminal?
        # process_outbox_entry handles validation, but let's just log and return.
        log(event="callback_skipped_no_url", sessionId=session_id)
        return

    # Process (idempotent)
    # Returns True if done (success or terminal failure)
    # Returns False if retry needed
    done = process_outbox_entry(session_id)
    
    if not done:
        # Retry needed. Check ledger for next attempt time.
        session = load_session(session_id)
        ledger = session.outboxEntry or {}
        next_ts = int(ledger.get("nextAttemptAt", 0) or 0)
        delay_ms = max(0, next_ts - int(time.time() * 1000))
        delay_sec = delay_ms / 1000.0
        
        # If delay is short (< 30s), sleep and retry inline (to avoid queue overhead)
        if delay_sec < 30:
            time.sleep(delay_sec)
            done = process_outbox_entry(session_id)
            if done:
                return

        # If still not done, reschedule
        try:
            q = get_queue()
            # Try RQ Scheduler if available (enqueue_in)
            if hasattr(q, "enqueue_in"):
                q.enqueue_in(timedelta(seconds=delay_sec), "app.queue.jobs.send_final_callback_job", session_id)
                log(event="callback_rescheduled", sessionId=session_id, delaySec=delay_sec)
                return
        except Exception:
            pass
        
        # Fallback: Raise exception so RQ native retry (if configured) handles it
        # or it goes to failed queue (manual intervention).
        # We rely on the ledger state to prevent duplicate processing even if RQ retries immediately.
        raise RuntimeError(f"Callback retry needed for session {session_id} (next attempt in {delay_sec:.1f}s)")


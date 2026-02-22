# app/core/guvi_callback.py
from typing import Optional
from app.observability.logging import log
from app.settings import settings

def enqueue_guvi_final_result(session, finalize_reason: Optional[str] = None) -> None:
    """
    Enqueue the new Group‑D callback path.
    Uses lazy imports to avoid circular dependencies with orchestrator/jobs.
    """
    if not settings.ENABLE_GUVI_CALLBACK:
        return

    # Persist finalize_reason into agentNotes (append; avoid duplicates)
    try:
        if finalize_reason:
            line = f"finalize_reason={finalize_reason}"
            notes = (getattr(session, "agentNotes", "") or "").strip()
            if not notes:
                session.agentNotes = line
            else:
                # Append only if not already present
                if line not in notes:
                    session.agentNotes = notes + " | " + line
    except Exception:
        pass

    mode = (getattr(settings, "FINAL_OUTPUT_MODE", "hybrid") or "hybrid").lower()

    # Idempotency: if already sent, do nothing
    try:
        if getattr(session, "callbackStatus", "none") == "sent":
            return
    except Exception:
        pass

    # Lazy imports to break cycle: orchestrator -> guvi_callback -> jobs -> client -> outbox
    from app.callback.sender import send_final_result_sync
    from app.queue.jobs import send_final_callback_job
    from app.queue.rq_conn import get_queue

    # Hybrid/sync mode: try immediate send first (deadline-bounded to fit 10s wait)
    if mode in ("sync", "hybrid"):
        try:
            ok = send_final_result_sync(
                session.sessionId,
                deadline_sec=float(getattr(settings, "FINAL_OUTPUT_DEADLINE_SEC", 8.0) or 8.0),
                max_retries=int(getattr(settings, "FINAL_OUTPUT_SYNC_RETRIES", 1) or 1),
            )
            if ok:
                try:
                    session.callbackStatus = "sent"
                except Exception:
                    pass
                return
        except Exception:
            pass

    # RQ mode or hybrid fallback: enqueue
    if mode in ("rq", "hybrid"):
        try:
            q = get_queue()
            job = q.enqueue(send_final_callback_job, session.sessionId)
            try:
                log(
                    event="callback_enqueued",
                    sessionId=session.sessionId,
                    job="send_final_callback_job",
                    rq_job_id=getattr(job, "id", "") or "",
                    finalize_reason=finalize_reason or "",
                    mode=mode,
                )
            except Exception:
                pass
            try:
                session.callbackStatus = "queued"
            except Exception:
                pass
        except Exception:
            try:
                session.callbackStatus = "failed"
            except Exception:
                pass

# app/core/guvi_callback.py
from typing import Optional
from app.queue.rq_conn import get_queue
from app.queue.jobs import send_final_callback_job
from app.observability.logging import log

def enqueue_guvi_final_result(session, finalize_reason: Optional[str] = None) -> None:
    """
    Enqueue the new Group‑D callback path:
      app.queue.jobs.send_final_callback_job(sessionId)
    The worker will run app/callback/client.py::send_final_result(sessionId),
    which builds the versioned payload, validates it, logs callback_payload_preview,
    and posts to the evaluator.
    """
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
    # Enqueue the new job (do NOT call the HTTP poster directly here)
    q = get_queue()
    job = q.enqueue(send_final_callback_job, session.sessionId)
    try:
        log(event="callback_enqueued",
            sessionId=session.sessionId,
            job="send_final_callback_job",
            rq_job_id=getattr(job, "id", "") or "",
            finalize_reason=finalize_reason or "")
    except Exception:
        pass

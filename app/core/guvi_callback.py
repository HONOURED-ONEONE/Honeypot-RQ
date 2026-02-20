"""
Callback enqueuer (rewired)
---------------------------
We keep the public function name `enqueue_guvi_final_result(...)` so the orchestrator
does not change, but we now enqueue the Group-D path:

    app.queue.jobs.send_final_callback_job(session_id)

This job calls app/callback/client.py::send_final_result(session_id), which:
  - builds the new payload (version + fingerprint) via app/callback/payloads.py,
  - validates shape locally,
  - logs `callback_payload_preview` + fingerprint,
  - posts to GUVI evaluator.

This replaces the legacy `_post_to_guvi(...)` worker path.
"""

from app.queue.jobs import send_final_callback_job
from app.observability.logging import log
from app.store.session_repo import save_session


def enqueue_guvi_final_result(session, finalize_reason: str = ""):
    """
    Public enqueuer used by orchestrator.
    Now enqueues the new job: app.queue.jobs.send_final_callback_job(sessionId).
    """
    # Persist session fields the worker/job needs (defensive)
    try:
        # Ensure finalize reason & counters are durable before queuing
        if finalize_reason:
            session.agentNotes = (session.agentNotes or "").strip() or f"finalize_reason={finalize_reason}"
        save_session(session)
    except Exception:
        # Non-influential: continue even if save fails
        pass

    # Enqueue the new job
    try:
        send_final_callback_job(session.sessionId)
        try:
            log(event="callback_enqueued",
                sessionId=session.sessionId,
                job="send_final_callback_job",
                finalize_reason=finalize_reason or "")
        except Exception:
            pass
    except Exception:
        # surface minimal log for observability; orchestrator will set callbackStatus accordingly
        try:
            log(event="callback_enqueue_failed",
                sessionId=session.sessionId,
                job="send_final_callback_job")
        except Exception:
            pass
        raise


# --------- DEPRECATED (left as no-op for safety) ----------
def _post_to_guvi(*args, **kwargs):
    """
    Deprecated. The worker should never call this in the new build.
    If you still see this in worker logs, the worker is running an old image.
    """
    raise RuntimeError("Deprecated path: _post_to_guvi is no longer used. Restart worker with the patched image.")

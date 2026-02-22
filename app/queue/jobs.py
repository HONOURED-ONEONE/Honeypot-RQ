from app.callback.outbox import process_outbox_entry
from app.observability.logging import log
from app.settings import settings

def send_final_callback_job(session_id: str):
    """
    Background job to process the callback outbox for a session.
    """
    if not settings.ENABLE_OUTBOX:
        return

    try:
        log(event="callback_job_start", sessionId=session_id)
        # process_outbox_entry handles the logic, retries, and persistence.
        # If it returns False (retry needed), we rely on RQ to retry if configured,
        # or we could re-enqueue here. The ledger prevents duplicate sends.
        process_outbox_entry(session_id)
    except Exception as e:
        log(event="callback_job_exception", sessionId=session_id, error=str(e))
        raise

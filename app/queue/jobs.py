from app.callback.client import send_final_result
from app.observability.logging import log


def send_final_callback_job(session_id: str):
    # Executed by RQ worker
    try:
        log(event="callback_job_start", sessionId=session_id)
    except Exception:
        pass
    send_final_result(session_id)

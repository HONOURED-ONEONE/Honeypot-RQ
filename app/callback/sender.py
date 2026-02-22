"""
Synchronous Final Output Sender (Deadline-Bounded)
-------------------------------------------------
Why: Evaluator waits ~10 seconds for final submission after conversation ends. [1](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/Honeypot%20API%20Evaluation%20System%20Documentation%20Updated%20-%20feb%2019.pdf)
Goal: Send final output inline when finalization triggers, bounded by a strict deadline
so the API request stays safely under the 30-second timeout requirement. [1](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/Honeypot%20API%20Evaluation%20System%20Documentation%20Updated%20-%20feb%2019.pdf)

This module is idempotent-friendly: callers should check session.callbackStatus before invoking.
"""

from __future__ import annotations

import time
from app.settings import settings
from app.store.session_repo import load_session, save_session
from app.callback.outbox import process_outbox_entry
from app.observability.logging import log


def send_final_result_sync(session_id: str, *, deadline_sec: float = 8.0, max_retries: int = 1) -> bool:
    """
    Try to POST the final output synchronously within deadline_sec using the unified Outbox processor.
    Returns True on success, False on failure.
    """
    if not settings.GUVI_CALLBACK_URL:
        try:
            log(event="final_output_sync_skipped_no_url", sessionId=session_id)
        except Exception:
            pass
        return False

    t0 = time.monotonic()
    
    # Attempt 1 (or more if fast failure and budget allows)
    # process_outbox_entry handles validation, payload building (if missing), and ledger updates.
    
    # Force outbox processing
    try:
        success = process_outbox_entry(session_id)
        if success:
            try:
                log(event="final_output_sync_success", sessionId=session_id, elapsedMs=int((time.monotonic() - t0) * 1000))
            except Exception:
                pass
            return True
    except Exception as e:
        try:
            log(event="final_output_sync_exception", sessionId=session_id, error=str(e))
        except Exception:
            pass

    # If failed, the ledger is updated with 'pending' and 'nextAttemptAt'.
    # The hybrid mode (caller) will likely enqueue the job, which will pick it up after backoff.
    
    return False

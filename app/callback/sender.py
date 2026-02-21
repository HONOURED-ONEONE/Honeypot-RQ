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
import json
import httpx

from app.settings import settings
from app.store.session_repo import load_session, save_session
from app.callback.payloads import build_final_payload
from app.callback.contract import sanitize_final_payload, validate_contract
from app.observability.logging import log
from app.store.redis_conn import get_redis


def _now_ms() -> int:
    return int(time.time() * 1000)


def send_final_result_sync(session_id: str, *, deadline_sec: float = 8.0, max_retries: int = 1) -> bool:
    """
    Try to POST the final output synchronously within deadline_sec.
    Returns True on success, False on failure (no raise).
    """
    if not settings.GUVI_CALLBACK_URL:
        # If callback URL isn't configured, we cannot send. Keep it as failed.
        try:
            log(event="final_output_sync_skipped_no_url", sessionId=session_id)
        except Exception:
            pass
        return False

    t0 = time.monotonic()
    deadline_sec = float(deadline_sec or 0.0)
    if deadline_sec <= 0:
        deadline_sec = 6.0

    session = load_session(session_id)

    # Build + sanitize payload
    payload = sanitize_final_payload(build_final_payload(session))
    ok, reason = validate_contract(payload)
    if not ok:
        # Never block send; just log
        try:
            log(event="final_output_sync_payload_invalid_autofix", sessionId=session_id, reason=reason)
        except Exception:
            pass
        payload = sanitize_final_payload(payload)

    # Store last payload for debugging/retry parity (already used elsewhere)
    try:
        if getattr(settings, "STORE_LAST_CALLBACK_PAYLOAD", True):
            r = get_redis()
            r.set(f"session:{session_id}:last_callback_payload", json.dumps(payload))
    except Exception:
        pass

    # Deadline-bounded send attempts
    attempt = 0
    last_err = None

    while attempt <= int(max_retries or 0):
        attempt += 1
        remaining = deadline_sec - (time.monotonic() - t0)
        if remaining <= 0:
            break

        # Per-attempt timeout: never exceed remaining time and never exceed configured timeout.
        per_try_timeout = min(float(getattr(settings, "CALLBACK_TIMEOUT_SEC", 5) or 5), max(0.5, remaining))

        try:
            try:
                log(
                    event="final_output_sync_attempt",
                    sessionId=session_id,
                    url=settings.GUVI_CALLBACK_URL,
                    attempt=int(attempt),
                    timeoutSec=float(per_try_timeout),
                )
            except Exception:
                pass

            with httpx.Client(timeout=per_try_timeout) as client:
                resp = client.post(settings.GUVI_CALLBACK_URL, json=payload)

            if 200 <= resp.status_code < 300:
                # Mark session as reported
                session.callbackStatus = "sent"
                session.state = "REPORTED"
                save_session(session)
                try:
                    log(
                        event="final_output_sync_success",
                        sessionId=session_id,
                        statusCode=int(resp.status_code),
                        elapsedMs=int((time.monotonic() - t0) * 1000),
                    )
                except Exception:
                    pass
                return True

            last_err = f"non_2xx:{resp.status_code}"
            try:
                log(
                    event="final_output_sync_non2xx",
                    sessionId=session_id,
                    statusCode=int(resp.status_code),
                    responseText=(resp.text or "")[:300],
                )
            except Exception:
                pass

        except Exception as e:
            last_err = f"{type(e).__name__}:{str(e)[:200]}"
            try:
                log(event="final_output_sync_exception", sessionId=session_id, error=str(last_err))
            except Exception:
                pass

        # backoff lightly but respect deadline
        remaining2 = deadline_sec - (time.monotonic() - t0)
        if remaining2 <= 0:
            break
        time.sleep(min(0.15, max(0.0, remaining2)))

    # Mark failed (so hybrid mode can queue)
    try:
        session.callbackStatus = "failed"
        save_session(session)
    except Exception:
        pass
    try:
        log(
            event="final_output_sync_failed",
            sessionId=session_id,
            elapsedMs=int((time.monotonic() - t0) * 1000),
            lastError=str(last_err or "unknown"),
        )
    except Exception:
        pass
    return False

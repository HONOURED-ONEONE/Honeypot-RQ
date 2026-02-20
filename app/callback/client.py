import httpx
import time
from app.settings import settings
from app.store.session_repo import load_session, save_session
from app.callback.payloads import build_final_payload
from app.observability.logging import log


def send_final_result(session_id: str):
    if not settings.GUVI_CALLBACK_URL:
        raise RuntimeError("GUVI_CALLBACK_URL is not set")

    session = load_session(session_id)
    payload = build_final_payload(session)

    # Send callback (executed in worker)
    start = time.time()
    try:
        log(
            event="callback_send_attempt",
            sessionId=session_id,
            url=settings.GUVI_CALLBACK_URL,
            timeoutSec=int(getattr(settings, "CALLBACK_TIMEOUT_SEC", 5) or 5),
            scamDetected=bool(getattr(session, "scamDetected", False)),
            totalMessagesExchanged=int(getattr(session, "totalMessagesExchanged", 0) or 0),
        )
        log(event="callback_payload_preview", sessionId=session_id, payload=payload)
    except Exception:
        pass

    try:
        with httpx.Client(timeout=settings.CALLBACK_TIMEOUT_SEC) as client:
            resp = client.post(settings.GUVI_CALLBACK_URL, json=payload)
        elapsed_ms = int((time.time() - start) * 1000)

        if 200 <= resp.status_code < 300:
            session.callbackStatus = "sent"
            session.state = "REPORTED"
            save_session(session)
            try:
                log(
                    event="callback_send_success",
                    sessionId=session_id,
                    statusCode=int(resp.status_code),
                    elapsedMs=int(elapsed_ms),
                )
            except Exception:
                pass
            return True

        # Non-2xx response
        session.callbackStatus = "failed"
        save_session(session)
        try:
            log(
                event="callback_send_failed",
                sessionId=session_id,
                statusCode=int(resp.status_code),
                elapsedMs=int(elapsed_ms),
                responseText=(resp.text or "")[:500],
            )
        except Exception:
            pass
        raise RuntimeError(f"Callback failed: {resp.status_code} {resp.text}")

    except Exception as e:
        elapsed_ms = int((time.time() - start) * 1000)
        # Ensure status is reflected in session for retries/diagnosis
        try:
            session.callbackStatus = "failed"
            save_session(session)
        except Exception:
            pass
        try:
            log(
                event="callback_send_exception",
                sessionId=session_id,
                elapsedMs=int(elapsed_ms),
                errorType=type(e).__name__,
                error=str(e)[:500],
            )
        except Exception:
            pass
        raise

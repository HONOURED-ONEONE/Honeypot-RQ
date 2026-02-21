import httpx
import time
import json
from app.settings import settings
from app.store.session_repo import load_session, save_session
from app.callback.payloads import build_final_payload, validate_final_payload
from app.callback.contract import sanitize_final_payload, validate_contract
from app.observability.logging import log
from app.store.redis_conn import get_redis


def send_final_result(session_id: str):
    if not settings.GUVI_CALLBACK_URL:
        raise RuntimeError("GUVI_CALLBACK_URL is not set")

    session = load_session(session_id)
    payload = build_final_payload(session)

    # Always sanitize to prevent contract drift impacting scoring.
    payload = sanitize_final_payload(payload)

    # Validate contract; if invalid, DO NOT abort—re-sanitize and proceed with best-effort payload.
    ok, reason = validate_contract(payload)
    if not ok:
        try:
            log(event="callback_payload_invalid_autofix",
                sessionId=session_id, reason=reason, payloadPreview=payload)
        except Exception:
            pass
        payload = sanitize_final_payload(payload)

    # Send callback (executed in worker)
    start = time.time()
    try:
        fp = "na"
        try:
            fp = str((payload.get("extractedIntelligence") or {}).get("_meta", {}).get("payloadFingerprint", "na"))
        except Exception:
            fp = "na"
        log(
            event="callback_send_attempt",
            sessionId=session_id,
            url=settings.GUVI_CALLBACK_URL,
            timeoutSec=int(getattr(settings, "CALLBACK_TIMEOUT_SEC", 5) or 5),
            scamDetected=bool(getattr(session, "scamDetected", False)),
            totalMessagesExchanged=int(getattr(session, "totalMessagesExchanged", 0) or 0),
            payloadFingerprint=fp,
        )
        log(event="callback_payload_preview", sessionId=session_id, payload=payload)
    except Exception:
        pass

    # Store a copy of the last payload in Redis for debug retrieval
    try:
        if getattr(settings, "STORE_LAST_CALLBACK_PAYLOAD", True):
            r = get_redis()
            r.set(f"session:{session_id}:last_callback_payload", json.dumps(payload))
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
                    payloadFingerprint=str(payload.get("payloadFingerprint","na")),
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
                payloadFingerprint=str(payload.get("payloadFingerprint","na")),
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
                payloadFingerprint=str(payload.get("payloadFingerprint","na")),
            )
        except Exception:
            pass
        raise

import httpx
from app.settings import settings
from app.store.session_repo import load_session, save_session
from app.callback.payloads import build_final_payload


def send_final_result(session_id: str):
    if not settings.GUVI_CALLBACK_URL:
        raise RuntimeError("GUVI_CALLBACK_URL is not set")

    session = load_session(session_id)
    payload = build_final_payload(session)

    # Send callback
    with httpx.Client(timeout=settings.CALLBACK_TIMEOUT_SEC) as client:
        resp = client.post(settings.GUVI_CALLBACK_URL, json=payload)

    if resp.status_code >= 200 and resp.status_code < 300:
        session.callbackStatus = "sent"
        session.state = "REPORTED"
        save_session(session)
        return True

    session.callbackStatus = "failed"
    save_session(session)
    raise RuntimeError(f"Callback failed: {resp.status_code} {resp.text}")

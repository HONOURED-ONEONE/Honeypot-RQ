import time


def normalize_honeypot_payload(payload: dict) -> dict:
    """
    Accepts multiple possible input shapes (e.g., GUVI tester variants) and converts
    them into the canonical structure expected by HoneypotRequest:

    {
      "sessionId": "...",
      "message": {"sender": "scammer|user", "text": "...", "timestamp": ...},
      "conversationHistory": [...],
      "metadata": {...}
    }
    """
    if payload is None:
        payload = {}

    # sessionId variants
    session_id = (
        payload.get("sessionId")
        or payload.get("session_id")
        or payload.get("session")
        or payload.get("id")
        or "tester-session"
    )

    # message variants
    msg = payload.get("message")

    if isinstance(msg, str):
        # If tester sends message as a plain string
        msg = {
            "sender": "scammer",
            "text": msg,
            "timestamp": int(time.time() * 1000),
        }
    elif not isinstance(msg, dict):
        # If tester sends text at top-level
        text = payload.get("text") or payload.get("messageText") or payload.get("content") or ""
        msg = {
            "sender": payload.get("sender", "scammer"),
            "text": text,
            "timestamp": int(time.time() * 1000),
        }

    # Fill defaults
    sender = msg.get("sender") or payload.get("sender") or "scammer"
    text = msg.get("text") or msg.get("message") or payload.get("text") or ""
    timestamp = msg.get("timestamp") or payload.get("timestamp") or int(time.time() * 1000)

    # conversationHistory variants
    conversation_history = payload.get("conversationHistory") or payload.get("history") or []
    if conversation_history is None:
        conversation_history = []

    metadata = payload.get("metadata") or {}

    return {
        "sessionId": session_id,
        "message": {"sender": sender, "text": text, "timestamp": timestamp},
        "conversationHistory": conversation_history,
        "metadata": metadata,
    }

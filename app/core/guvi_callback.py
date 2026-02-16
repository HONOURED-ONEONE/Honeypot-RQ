# app/core/guvi_callback.py
from typing import Optional

import requests
from rq import Queue

from app.store.redis_conn import get_redis
from app.settings import settings


GUVI_ENDPOINT_DEFAULT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"


def _build_payload(session, finalize_reason: Optional[str] = None) -> dict:
    intel = session.extractedIntelligence

    # PS-2 mandatory payload shape
    # https://hackathon.guvi.in/api/updateHoneyPotFinalResult
    payload = {
        "sessionId": session.sessionId,
        "scamDetected": bool(session.scamDetected),
        "totalMessagesExchanged": int(getattr(session, "turnIndex", 0) or session.totalMessagesExchanged or 0),
        "extractedIntelligence": {
            "bankAccounts": getattr(intel, "bankAccounts", []) or [],
            "upiIds": getattr(intel, "upiIds", []) or [],
            "phishingLinks": getattr(intel, "phishingLinks", []) or [],
            "phoneNumbers": getattr(intel, "phoneNumbers", []) or [],
            # If you don’t have suspiciousKeywords yet, send empty list for now.
            "suspiciousKeywords": getattr(intel, "suspiciousKeywords", []) or [],
        },
        "agentNotes": (getattr(session, "agentNotes", "") or "").strip(),
    }

    # Optional: include finalize reason in agentNotes to help debugging (not required)
    if finalize_reason and payload["agentNotes"] == "":
        payload["agentNotes"] = f"finalize_reason={finalize_reason}"

    return payload


def _post_to_guvi(payload: dict) -> None:
    url = settings.GUVI_CALLBACK_URL or GUVI_ENDPOINT_DEFAULT
    requests.post(url, json=payload, timeout=settings.CALLBACK_TIMEOUT_SEC)


def enqueue_guvi_final_result(session, finalize_reason: Optional[str] = None) -> None:
    payload = _build_payload(session, finalize_reason=finalize_reason)

    q = Queue(settings.RQ_QUEUE_NAME, connection=get_redis())

    # enqueue the HTTP post task
    q.enqueue(
        _post_to_guvi,
        payload,
        job_timeout=settings.CALLBACK_TIMEOUT_SEC + 5,  # small buffer
        result_ttl=0,
        failure_ttl=0,
    )
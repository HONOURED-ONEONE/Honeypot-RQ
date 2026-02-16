# app/core/orchestrator.py
"""
Orchestrator Invariants (Non-Negotiable)
- The orchestrator NEVER decides what to ask.
- The orchestrator ONLY coordinates:
  - session lifecycle
  - intent sequencing
  - responder invocation
  - finalize gating
"""
from app.llm.detector import detect_scam
from app.store.session_repo import load_session, save_session
from app.core.broken_flow_controller import choose_next_action
from app.llm.responder import generate_agent_reply
from app.core.finalize import should_finalize
from app.observability.logging import log

from app.settings import settings as app_settings
from app.core.guvi_callback import enqueue_guvi_final_result  # ✅ NEW


def handle_event(req):
    # Load session
    session = load_session(req.sessionId)
    result = detect_scam(req, session)

    if result["scamDetected"] and result["confidence"] >= app_settings.SCAM_THRESHOLD:
        if not getattr(session, "scamType", None) or session.scamType is None:
            session.scamType = result["scamType"]

    session.scam_type = getattr(session, "scam_type", None)

    # Controller
    controller_out = choose_next_action(
        session=session,
        latest_text=req.message.text or "",
        intel_dict=session.extractedIntelligence.__dict__,
        detection_dict=req.detection or {},  # ✅ detection is dict per schema
        settings=app_settings,
    )

    intent = controller_out.get("intent")
    bf_state = controller_out.get("bf_state")
    force_finalize = controller_out.get("force_finalize", False)
    reason = controller_out.get("reason", "normal_flow")

    assert intent is not None, "Intent must be resolved before response generation"

    # Finalize gating: should_finalize returns Optional[str] reason
    finalize_reason = "force_finalize" if force_finalize else should_finalize(session)
    finalized = finalize_reason is not None

    # Generate reply
    reply_text = generate_agent_reply(req=req, session=session, intent=intent)

    # --- Mandatory Callback Trigger (PS-2) ---
    # Only when scamDetected is true and finalization condition is met
    # Ensure it triggers exactly once.
    if finalized and session.scamDetected and session.callbackStatus in ("none", "failed"):
        # Keep counters synced for callback payload
        session.totalMessagesExchanged = int(getattr(session, "turnIndex", 0) or 0)

        # Mark lifecycle and enqueue callback
        session.state = "READY_TO_REPORT"
        try:
            enqueue_guvi_final_result(session, finalize_reason=finalize_reason)
            session.callbackStatus = "queued"
        except Exception:
            session.callbackStatus = "failed"

    # Persist session
    save_session(session)

    # Observability (non-influential)
    try:
        log(
            event="turn_processed",
            sessionId=session.sessionId,
            bf_state=bf_state,
            intent=intent,
            finalize_reason=finalize_reason or "",
            totalMessagesExchanged=getattr(session, "turnIndex", 0),
        )
    except Exception:
        pass

    # PS-2 API output should be: {"status":"success","reply":"..."} (routes adds status)
    return {"reply": reply_text}
# app/core/orchestrator.py
"""
Orchestrator Invariants (Non-Negotiable)
- Conversation turns must be persisted for context and counting.
- The orchestrator NEVER decides what to ask.
- The orchestrator ONLY coordinates:
  - session lifecycle
  - intent sequencing
  - responder invocation
  - finalize gating
"""
import time
from typing import List, Dict, Any
from app.llm.detector import detect_scam
from app.store.session_repo import load_session, save_session
from app.core.broken_flow_controller import choose_next_action
from app.llm.responder import generate_agent_reply
from app.core.finalize import should_finalize
from app.observability.logging import log

from app.settings import settings as app_settings
from app.core.guvi_callback import enqueue_guvi_final_result # ✅ NEW
from app.intel.extractor import update_intelligence_from_text  # ✅ P0.1: registry-driven extraction


def _coerce_history_items(history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    P2.1: Normalize evaluator-provided conversationHistory into our
    canonical {sender,text,timestamp} dicts for session storage.
    Defensive against missing/odd fields.
    """
    out: List[Dict[str, Any]] = []
    now_ms = int(time.time() * 1000)
    for m in history or []:
        try:
            sender = (m.get("sender") or "scammer")
            text = (m.get("text") or "")
            ts = m.get("timestamp")
            # Accept either epoch ms or iso strings; if absent, use now.
            if isinstance(ts, (int, float)):
                tsv = int(ts)
            else:
                tsv = now_ms
            out.append({"sender": sender, "text": text, "timestamp": tsv})
        except Exception:
            # Skip malformed entries; keep the session stable
            continue
    return out


def handle_event(req):
    # Load session
    session = load_session(req.sessionId)

    # ✅ P2.1: Bootstrap conversation from evaluator-provided history (first load / empty session)
    try:
        if not session.conversation:
            req_hist = getattr(req, "conversationHistory", None) or []
            boot = _coerce_history_items(req_hist)
            if boot:
                session.conversation.extend(boot)
                session.turnIndex = int(len(session.conversation))
    except Exception:
        # Non-influential safety net
        pass

    # ✅ P0.3: Persist the incoming message and increment counters
    try:
        incoming_ts = req.message.timestamp
    except Exception:
        incoming_ts = int(time.time() * 1000)
    try:
        session.conversation.append({
            "sender": getattr(req.message, "sender", "scammer"),
            "text": getattr(req.message, "text", "") or "",
            "timestamp": incoming_ts,
        })
        session.turnIndex = int(getattr(session, "turnIndex", 0) or 0) + 1
    except Exception:
        # Keep processing even if persistence fails (non-influential)
        pass

    result = detect_scam(req, session)
    # ✅ P0.4: Persist detector outcome to session (required for finalize + callback)
    try:
        session.scamDetected = bool(result.get("scamDetected", False))
    except Exception:
        session.scamDetected = False
    try:
        session.confidence = float(result.get("confidence", 0.0) or 0.0)
    except Exception:
        session.confidence = 0.0

    # Maintain scam type consistently
    try:
        detected_type = str(result.get("scamType") or "UNKNOWN")
        # Prefer keeping previously set scamType if already present and non-empty
        if not getattr(session, "scamType", None):
            session.scamType = detected_type
        else:
            # ensure it is a string
            session.scamType = str(session.scamType)
    except Exception:
        session.scamType = "UNKNOWN"
    # ✅ P1.1: Keep controller-facing alias in sync
    session.scam_type = session.scamType or "UNKNOWN"

    # ✅ P0.1: Intelligence extraction BEFORE controller/finalize
    #    - Extract from the latest incoming message
    #    - Optionally catch up on a small recent window of conversationHistory
    latest_text = req.message.text or ""
    if latest_text:
        update_intelligence_from_text(session, latest_text)
    try:
        history = getattr(req, "conversationHistory", None) or []
        for m in history[-6:]:
            text = (m.get("text") if isinstance(m, dict) else "") or ""
            if text:
                update_intelligence_from_text(session, text)
    except Exception:
        # Maintain stability if history parsing fails (non-influential)
        pass

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

    # ✅ P0.3: Persist the agent reply and increment counters
    try:
        reply_ts = int(time.time() * 1000)
        session.conversation.append({
            "sender": "user",
            "text": reply_text or "",
            "timestamp": reply_ts,
        })
        session.turnIndex = int(getattr(session, "turnIndex", 0) or 0) + 1
    except Exception:
        # Non-influential; continue even if append fails
        pass

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
import time
from rq import Retry
from dataclasses import asdict

from app.api.schemas import HoneypotRequest
from app.store.session_repo import load_session, save_session
from app.intel.extractor import update_intelligence_from_text
from app.core.finalize import should_finalize
from app.core.notes import build_agent_notes
from app.queue.rq_conn import get_queue
from app.queue.jobs import send_final_callback_job
from app.llm.detector import detect_scam
from app.llm.responder import generate_agent_reply
from app.core.broken_flow_controller import choose_next_action
from app.settings import settings
from app.observability.logging import log

NON_SPAM_REPLY = "ok"


def _now_ms() -> int:
    return int(time.time() * 1000)


def handle_event(req: HoneypotRequest) -> str:
    start_time = time.time()
    session = load_session(req.sessionId)

    # Always merge request.conversationHistory into session.conversation if session is fresh
    if not session.conversation and req.conversationHistory:
        for msg in req.conversationHistory:
            session.conversation.append(msg.model_dump())

    # Append incoming message
    session.totalMessagesExchanged += 1
    session.conversation.append(req.message.model_dump())

    # Trim to MAX_CONTEXT_MESSAGES
    if len(session.conversation) > settings.MAX_CONTEXT_MESSAGES:
        session.conversation = session.conversation[-settings.MAX_CONTEXT_MESSAGES:]

    detection = detect_scam(req, session)
    # Scam detected is sticky
    session.scamDetected = session.scamDetected or bool(detection.get("scamDetected"))
    session.confidence = max(session.confidence, float(detection.get("confidence") or 0.0))
    if detection.get("scamType"):
        session.scamType = detection.get("scamType")

    session.lastUpdatedAtEpoch = int(time.time())

    # Only engage if scam detected
    if not session.scamDetected:
        session.state = "MONITORING"
        save_session(session)
        return NON_SPAM_REPLY

    if session.state in ("INIT", "MONITORING"):
        session.state = "ENGAGED"

    # Fix 2: Extraction runs on joined window of recent scammer messages
    scammer_texts = [m.get("text", "") for m in session.conversation if m.get("sender") == "scammer"]
    joined_scammer_text = " ".join(scammer_texts[-6:])
    if joined_scammer_text:
        update_intelligence_from_text(session, joined_scammer_text)

    session.agentNotes = build_agent_notes(detection)

    # Broken-Flow Controller
    intel_dict = asdict(session.extractedIntelligence)
    bf_action = choose_next_action(session, req.message.text, intel_dict, detection, settings)

    llm_start = time.time()
    try:
        reply = generate_agent_reply(req, session, intent=bf_action["intent"])
    except Exception:
        reply = "ok sir, kindly guide what exactly i should do next."
    llm_latency_ms = int((time.time() - llm_start) * 1000)

    # Store agent reply for multi-turn continuity and repetition control
    session.totalMessagesExchanged += 1
    session.conversation.append({
        "sender": "agent",
        "text": reply,
        "timestamp": _now_ms(),
    })

    finalize_reason = ""
    if bf_action.get("force_finalize"):
        finalize_reason = "controller_force"
    elif should_finalize(session):
        finalize_reason = "policy_match"

    if finalize_reason:
        if session.callbackStatus not in ("queued", "sent"):
            q = get_queue()
            q.enqueue(
                send_final_callback_job,
                session.sessionId,
                retry=Retry(max=5, interval=[5, 15, 30, 60, 120]),
            )
            session.callbackStatus = "queued"
            session.state = "READY_TO_REPORT"

    save_session(session)

    # Structured logging per turn
    duration_ms = int((time.time() - start_time) * 1000)
    log("turn_processed",
        sessionId=session.sessionId,
        turn_index=session.totalMessagesExchanged // 2,
        bf_state=bf_action.get("bf_state"),
        intent=bf_action.get("intent"),
        bf_repeat_count=session.bf_repeat_count,
        bf_no_progress_count=session.bf_no_progress_count,
        bf_secondary_bounce_count=session.bf_secondary_bounce_count,
        fallback_used=session.bf_fallback_used,
        ioc_categories_found=len([k for k, v in intel_dict.items() if v and isinstance(v, list)]),
        finalize_reason=finalize_reason,
        total_latency_ms=duration_ms,
        llm_latency_ms=llm_latency_ms
    )

    return reply

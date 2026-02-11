import time
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Tuple

from rq import Retry

from app.api.schemas import HoneypotRequest
from app.core import state_machine as sm
from app.core.finalize import should_finalize
from app.core.notes import build_agent_notes
from app.core.broken_flow_controller import choose_next_action
from app.intel.extractor import update_intelligence_from_text
from app.llm.detector import detect_scam
from app.llm.responder import generate_agent_reply
from app.observability.logging import log
from app.queue.jobs import send_final_callback_job
from app.queue.rq_conn import get_queue
from app.settings import settings
from app.store.session_repo import load_session, save_session

NON_SPAM_REPLY = "ok"


def _now_ms() -> int:
    return int(time.time() * 1000)


def _safe_model_dump(obj: Any) -> Dict[str, Any]:
    """Support Pydantic v2 (model_dump), dicts, or simple objects."""
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    md = getattr(obj, "model_dump", None)
    if callable(md):
        return md()
    # fallback for unknown shapes
    out = {}
    for k in ("sender", "text", "timestamp"):
        if hasattr(obj, k):
            out[k] = getattr(obj, k)
    return out


def _normalize_sender(sender: Optional[str]) -> str:
    """
    Normalize sender labels to keep extraction/controller deterministic.
    We treat missing sender as 'scammer' because the incoming event is from scammer side.
    """
    s = (sender or "").strip().lower()
    if not s:
        return "scammer"
    # normalize common variants
    if s in ("attacker", "fraudster"):
        return "scammer"
    if s in ("honeypot", "assistant", "bot"):
        return "agent"
    return s


def _msg_key(m: Dict[str, Any]) -> Tuple[str, str, str]:
    """Dedupe key for messages. Timestamp is optional; fall back to sender+text."""
    sender = _normalize_sender(m.get("sender"))
    text = (m.get("text") or "").strip()
    ts = str(m.get("timestamp") or "")
    # if timestamp missing, still stable enough
    return (sender, text, ts)


def _merge_conversation_history(session, req: HoneypotRequest) -> None:
    """
    Always merge request.conversationHistory into session.conversation with dedupe.
    This prevents missing prior scammer messages when pods restart or Redis state is partial.
    """
    if not getattr(session, "conversation", None):
        session.conversation = []

    existing_keys = {_msg_key(m) for m in session.conversation if isinstance(m, dict)}
    hist = getattr(req, "conversationHistory", None) or []

    for msg in hist:
        d = _safe_model_dump(msg)
        d["sender"] = _normalize_sender(d.get("sender"))
        d["timestamp"] = d.get("timestamp") or _now_ms()
        k = _msg_key(d)
        if k not in existing_keys and d.get("text"):
            session.conversation.append(d)
            existing_keys.add(k)


def _append_incoming_message(session, req: HoneypotRequest) -> None:
    """Append incoming message (from scammer) and normalize sender."""
    d = _safe_model_dump(req.message)
    d["sender"] = _normalize_sender(d.get("sender"))  # if missing -> scammer
    d["timestamp"] = d.get("timestamp") or _now_ms()
    session.conversation.append(d)


def _append_agent_message(session, reply: str) -> None:
    session.conversation.append(
        {
            "sender": "agent",
            "text": reply,
            "timestamp": _now_ms(),
        }
    )


def _trim_conversation(session) -> None:
    max_msgs = int(getattr(settings, "MAX_CONTEXT_MESSAGES", 24))
    if len(session.conversation) > max_msgs:
        session.conversation = session.conversation[-max_msgs:]


def _count_agent_turns(conversation: List[Dict[str, Any]]) -> int:
    """More robust than totalMessagesExchanged//2."""
    return sum(1 for m in conversation if _normalize_sender(m.get("sender")) == "agent")


def _extract_from_recent_scammer_text(session, window: int = 6) -> None:
    """
    Update intelligence from a joined window of recent scammer messages.
    Also protects against sender-label mismatch by normalizing sender.
    """
    scammer_texts = [
        (m.get("text") or "")
        for m in session.conversation
        if _normalize_sender(m.get("sender")) == "scammer"
    ]
    joined = " ".join([t for t in scammer_texts[-window:] if t])
    if joined:
        update_intelligence_from_text(session, joined)


def handle_event(req: HoneypotRequest) -> str:
    start_time = time.time()
    session = load_session(req.sessionId)

    # Ensure required fields exist even for older sessions (backward compatible)
    if not getattr(session, "conversation", None):
        session.conversation = []
    if not hasattr(session, "bf_fallback_used"):
        session.bf_fallback_used = False
    if not hasattr(session, "callbackStatus"):
        session.callbackStatus = "pending"

    # 1) Merge conversationHistory EVERY time (dedupe)
    _merge_conversation_history(session, req)

    # 2) Append incoming message and normalize sender
    _append_incoming_message(session, req)

    # 3) Trim context
    _trim_conversation(session)

    # 4) Make totalMessagesExchanged accurate (count all messages we have)
    session.totalMessagesExchanged = len(session.conversation)

    # 5) Update activity timestamp
    session.lastUpdatedAtEpoch = int(time.time())

    # 6) Detection (scamDetected is sticky)
    detection = detect_scam(req, session)
    session.scamDetected = bool(getattr(session, "scamDetected", False)) or bool(
        detection.get("scamDetected")
    )
    session.confidence = max(float(getattr(session, "confidence", 0.0)), float(detection.get("confidence") or 0.0))
    if detection.get("scamType"):
        session.scamType = detection.get("scamType")

    # If not scam: keep monitoring and return non-spam reply
    if not session.scamDetected:
        session.state = sm.MONITORING
        save_session(session)
        return NON_SPAM_REPLY

    # Transition into engaged state
    if session.state in (sm.INIT, sm.MONITORING, "", None):
        session.state = sm.ENGAGED

    # 7) Intel extraction (two-layer safety):
    #    a) Always extract from the latest incoming message text (guarantees no miss)
    #    b) Also extract from recent scammer window (covers multi-turn & repeats)
    try:
        update_intelligence_from_text(session, req.message.text)
    except Exception:
        # extraction must never crash orchestrator
        pass

    try:
        _extract_from_recent_scammer_text(session, window=6)
    except Exception:
        pass

    # 8) Agent notes based on detection + (optionally) extracted intel
    # If your build_agent_notes supports intel, pass it; otherwise keep detection-only.
    try:
        session.agentNotes = build_agent_notes(detection)
    except Exception:
        session.agentNotes = ""

    # 9) Broken-Flow controller chooses next intent deterministically
    intel_dict = asdict(session.extractedIntelligence)
    bf_action = choose_next_action(session, req.message.text, intel_dict, detection, settings)

    # 10) Generate reply (intent-driven)
    llm_start = time.time()
    session.bf_fallback_used = False
    try:
        reply = generate_agent_reply(req, session, intent=bf_action["intent"])
    except Exception:
        # Fallback should be neutral and safe (no OTP guidance)
        reply = "ok sir. please share the official website/helpline so i can verify safely."
        session.bf_fallback_used = True
    llm_latency_ms = int((time.time() - llm_start) * 1000)

    # 11) Store agent reply for continuity
    _append_agent_message(session, reply)
    _trim_conversation(session)
    session.totalMessagesExchanged = len(session.conversation)

    # 12) Finalize decision
    finalize_reason = ""
    if bf_action.get("force_finalize"):
        finalize_reason = "controller_force"
    elif should_finalize(session):
        finalize_reason = "policy_match"

    # 13) Callback enqueue (idempotent)
    if finalize_reason:
        if session.callbackStatus not in ("queued", "sent"):
            q = get_queue()
            q.enqueue(
                send_final_callback_job,
                session.sessionId,
                retry=Retry(max=5, interval=[5, 15, 30, 60, 120]),
            )
            session.callbackStatus = "queued"
            session.state = sm.READY_TO_REPORT

    save_session(session)

    # 14) Structured logging per turn
    duration_ms = int((time.time() - start_time) * 1000)
    turn_index = _count_agent_turns(session.conversation)

    # Refresh intel snapshot for logging (post-reply)
    intel_dict_now = asdict(session.extractedIntelligence)
    ioc_categories_found = sum(
        1 for k, v in intel_dict_now.items()
        if isinstance(v, list) and len(v) > 0
    )

    log(
        "turn_processed",
        sessionId=session.sessionId,
        turn_index=turn_index,
        bf_state=bf_action.get("bf_state"),
        intent=bf_action.get("intent"),
        bf_repeat_count=getattr(session, "bf_repeat_count", 0),
        bf_no_progress_count=getattr(session, "bf_no_progress_count", 0),
        bf_secondary_bounce_count=getattr(session, "bf_secondary_bounce_count", 0),
        fallback_used=getattr(session, "bf_fallback_used", False),
        ioc_categories_found=ioc_categories_found,
        finalize_reason=finalize_reason,
        total_latency_ms=duration_ms,
        llm_latency_ms=llm_latency_ms,
    )

    return reply
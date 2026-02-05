from rq import Retry

from app.api.schemas import HoneypotRequest
from app.store.session_repo import load_session, save_session
from app.intel.extractor import update_intelligence_from_text
from app.core.finalize import should_finalize
from app.core.notes import build_agent_notes
from app.queue.rq_conn import get_queue
from app.queue.jobs import send_final_callback_job
from app.llm.detector import detect_scam
from app.llm.responder import generate_agent_reply


def handle_event(req: HoneypotRequest) -> str:
    session = load_session(req.sessionId)

    # Append incoming message
    session.totalMessagesExchanged += 1
    session.conversation.append(req.message.model_dump())

    detection = detect_scam(req, session)
    session.scamDetected = bool(detection.get("scamDetected"))
    session.confidence = float(detection.get("confidence") or 0.0)
    session.scamType = detection.get("scamType")

    if session.scamDetected:
        if session.state in ("INIT", "MONITORING"):
            session.state = "ENGAGED"

        if req.message.sender == "scammer":
            update_intelligence_from_text(session, req.message.text)

        session.agentNotes = build_agent_notes(detection)

        # Never allow LLM exceptions to crash the request
        try:
            reply = generate_agent_reply(req, session)
        except Exception:
            reply = "ok, what exactly do i need to do next?"

        if should_finalize(session):
            if session.callbackStatus not in ("queued", "sent"):
                q = get_queue()
                q.enqueue(
                    send_final_callback_job,
                    session.sessionId,
                    retry=Retry(max=5, interval=[5, 15, 30, 60, 120]),
                )
                session.callbackStatus = "queued"
                session.state = "READY_TO_REPORT"

    else:
        session.state = "MONITORING"
        reply = "ok, what exactly do i need to do?"

    save_session(session)
    return reply

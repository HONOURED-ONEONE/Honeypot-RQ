# app/core/orchestrator.py

"""
Orchestrator Invariants (Non-Negotiable)

- The orchestrator NEVER decides what to ask.
- The orchestrator ONLY coordinates:
    - session lifecycle
    - intent sequencing
    - responder invocation
    - finalize gating
- All conversational pressure surfaces are expressed exclusively via intents.
- Intents are derived solely from:
    - registry-backed artifact state
    - broken-flow controller output
- Closing behavior is gated strictly by finalize checks.
"""

from app.store.session_repo import load_session, save_session
from app.core.broken_flow_controller import choose_next_action
from app.llm.responder import generate_agent_reply
from app.core.finalize import should_finalize
from app.observability.logging import log
from app.settings import settings as app_settings


def handle_event(req):
    """
    Main orchestration entrypoint.

    Responsibilities:
    - Load session
    - Delegate intent selection to controller
    - Delegate phrasing to responder
    - Apply finalize gating
    - Persist session state

    This function MUST NOT:
    - decide content
    - infer artifacts
    - alter intent semantics
    """

    # ------------------------------------------------------------------
    # Load session (authoritative state container)
    # ------------------------------------------------------------------
    session = load_session(req.sessionId)

    # ------------------------------------------------------------------
    # Delegate intent decision to broken-flow controller
    # ------------------------------------------------------------------
    controller_out = choose_next_action(
        session=session,
        latest_text=req.message.text or "",
        intel_dict=session.extractedIntelligence.__dict__,
        detection_dict=req.detection.__dict__ if req.detection else {},
        settings=app_settings
    )

    intent = controller_out.get("intent")
    bf_state = controller_out.get("bf_state")
    force_finalize = controller_out.get("force_finalize", False)
    reason = controller_out.get("reason", "normal_flow")

    # Invariant: orchestrator does not decide content
    assert intent is not None, "Intent must be resolved before response generation"

    # ------------------------------------------------------------------
    # Finalize gating (registry-driven only)
    # ------------------------------------------------------------------
    finalized = False
    if force_finalize:
        finalized = True
    else:
        finalized = should_finalize(session)

    # ------------------------------------------------------------------
    # Delegate phrasing to responder (intent-driven only)
    # ------------------------------------------------------------------
    reply_text = generate_agent_reply(
        req=req,
        session=session,
        intent=intent,
    )

    # ------------------------------------------------------------------
    # Persist session state
    # ------------------------------------------------------------------
    save_session(session)

    # ------------------------------------------------------------------
    # Observability (non-influential)
    # ------------------------------------------------------------------
    log(
        event="turn_processed",
        sessionId=session.sessionId,
        bf_state=bf_state,
        intent=intent,
        finalize_reason=reason if finalized else "",
        totalMessagesExchanged=session.turnIndex,
    )

    # ------------------------------------------------------------------
    # Return response envelope
    # ------------------------------------------------------------------
    return {
        "reply": reply_text,
        "finalized": finalized,
    }

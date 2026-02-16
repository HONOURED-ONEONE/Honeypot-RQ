from typing import List, Optional

from app.core.broken_flow_constants import (
    HIGH_YIELD_ARTIFACT_INTENTS,
    SECONDARY_FAILURE_INTENTS,
    SINGLE_USE_BOUNDARY_INTENTS,
    CLOSING_INTENTS,
)
from app.core.state_machine import determine_next_intent
from app.core.session_repo import SessionState
from app.core.settings import settings


def _get_repeat_limit() -> int:
    """
    Defensive access to repeat limit.
    Prevents crash if settings is misconfigured.
    """
    return getattr(settings, "BF_REPEAT_LIMIT", 2)


def _filter_intents(candidates: List[str], allowed_group: set) -> List[str]:
    """
    Restrict candidate intents to a specific intent group.
    """
    return [i for i in candidates if i in allowed_group]


def choose_next_action(
    session: SessionState,
    artifact_state: dict,
    detection: Optional[dict] = None,
) -> str:
    """
    Controller responsible for selecting the next intent.

    Invariants:
    - Controller never decides content, only intent.
    - Artifact registry drives progression.
    - Boundary loops are capped.
    - Escalation enforced after repeat threshold.
    - Finalization gating remains external.
    """

    # Determine baseline candidate intents from state machine
    candidates: List[str] = determine_next_intent(
        artifact_state=artifact_state,
        session=session,
        detection=detection or {},
    )

    if not candidates:
        return None

    last_intent = session.last_intent
    repeat_limit = _get_repeat_limit()

    # ------------------------------------------------------------------
    # Repeat Tracking
    # ------------------------------------------------------------------
    if last_intent and candidates and last_intent == candidates[0]:
        session.bf_repeat_count += 1
    else:
        session.bf_repeat_count = 0

    # ------------------------------------------------------------------
    # Escalation Rule:
    # If boundary intent repeats beyond threshold,
    # force transition into high-yield artifact acquisition.
    # ------------------------------------------------------------------
    if (
        last_intent in SINGLE_USE_BOUNDARY_INTENTS
        and session.bf_repeat_count >= repeat_limit
    ):
        high_yield = _filter_intents(candidates, HIGH_YIELD_ARTIFACT_INTENTS)

        if high_yield:
            selected = high_yield[0]
            session.last_intent = selected
            session.bf_repeat_count = 0
            return selected

        secondary = _filter_intents(candidates, SECONDARY_FAILURE_INTENTS)

        if secondary:
            selected = secondary[0]
            session.last_intent = selected
            session.bf_repeat_count = 0
            return selected

    # ------------------------------------------------------------------
    # Prevent infinite closing loops
    # ------------------------------------------------------------------
    if last_intent in CLOSING_INTENTS and session.bf_repeat_count > 0:
        session.bf_repeat_count = 0

    # ------------------------------------------------------------------
    # Default Selection (First Valid Candidate)
    # ------------------------------------------------------------------
    selected = candidates[0]
    session.last_intent = selected

    return selected
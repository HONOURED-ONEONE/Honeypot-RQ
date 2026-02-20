import pytest
from app.store.models import SessionState
from app.core.broken_flow_controller import (
    choose_next_action,
    BF_S1, BF_S2, BF_S3, BF_S4, BF_S5,
    INT_ACK_CONCERN,
    INT_ASK_TICKET_REF,
    INT_ASK_ALT_VERIFICATION,
    INT_ASK_OFFICIAL_HELPLINE,
)

class MockSettings:
    BF_ENABLED = True
    BF_MAX_TURNS = 15
    BF_NO_PROGRESS_TURNS = 2
    BF_REPEAT_LIMIT = 2
    BF_SECONDARY_BOUNCE_LIMIT = 1
    BF_MIN_IOC_CATEGORIES = 2
    BF_LLM_REPHRASE = False
    FINALIZE_MIN_IOC_CATEGORIES = 2

def test_escalation_on_sustained_no_progress():
    session = SessionState(sessionId="test-escalation")
    session.bf_state = BF_S2
    # settings.BF_NO_PROGRESS_TURNS is 2, so 2*2 = 4
    session.bf_no_progress_count = 4
    
    settings = MockSettings()
    intel = {"phoneNumbers": [], "upiIds": [], "bankAccounts": [], "phishingLinks": []}
    
    action = choose_next_action(session, "hello", intel, {}, settings)
    # Should have escalated to BF_S4
    assert session.bf_state == BF_S4

def test_ack_repetition_guard_pivots_away():
    from app.intel.artifact_registry import artifact_registry
    session = SessionState(sessionId="test-ack-repetition")
    session.bf_state = BF_S2
    # ACK INT_ACK_CONCERN dominated the window
    session.bf_recent_intents = [INT_ACK_CONCERN, INT_ACK_CONCERN]
    
    settings = MockSettings()

    # Disable ALL artifacts so we force exhaustion/fallback behavior
    for key in artifact_registry.artifacts:
        artifact_registry.artifacts[key].enabled = False

    try:
        intel = {"phoneNumbers": [], "upiIds": [], "bankAccounts": [], "phishingLinks": []}
        action = choose_next_action(session, "hello", intel, {}, settings)
        # Should have pivoted away from ACK_CONCERN
        assert action["intent"] != INT_ACK_CONCERN
        assert action["reason"] == "ack_repetition_breaker"
    finally:
        for key in artifact_registry.artifacts:
            artifact_registry.artifacts[key].enabled = True

def test_ack_repetition_guard_pivots_to_ticket_ref_if_intel_present():
    session = SessionState(sessionId="test-ack-to-ticket")
    session.bf_state = BF_S2
    session.bf_recent_intents = [INT_ACK_CONCERN, INT_ACK_CONCERN]
    
    settings = MockSettings()
    # Link present but no phone/upi/bank yet
    intel = {"phoneNumbers": [], "upiIds": [], "bankAccounts": [], "phishingLinks": ["http://link"]}
    
    action = choose_next_action(session, "hello", intel, {}, settings)
    
    # Hits progress_ticket_ref because got_link is True and it would have picked an ACK or ALT_VERIF
    assert action["intent"] == INT_ASK_TICKET_REF
    assert action["reason"] == "progress_ticket_ref"

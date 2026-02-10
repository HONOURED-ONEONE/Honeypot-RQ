import pytest
from dataclasses import asdict
from app.store.models import SessionState, Intelligence
from app.core.broken_flow_constants import *
from app.core.broken_flow_controller import choose_next_action, compute_ioc_signature
from app.llm.responder import _safety_filter, generate_agent_reply
from app.core.finalize import should_finalize

class MockSettings:
    BF_ENABLED = True
    BF_MAX_TURNS = 15
    BF_NO_PROGRESS_TURNS = 2
    BF_REPEAT_LIMIT = 2
    BF_SECONDARY_BOUNCE_LIMIT = 1
    BF_MIN_IOC_CATEGORIES = 2
    BF_LLM_REPHRASE = False
    FINALIZE_MIN_IOC_CATEGORIES = 2
    FINALIZE_MIN_TURNS = 5
    INACTIVITY_TIMEOUT_SEC = 180

@pytest.fixture
def session():
    return SessionState(sessionId="test_session")

@pytest.fixture
def settings():
    return MockSettings()

def test_otp_refusal_once(session, settings):
    intel_dict = asdict(session.extractedIntelligence)
    
    # First OTP request
    action = choose_next_action(session, "send me the otp", intel_dict, {}, settings)
    assert action["intent"] == INT_REFUSE_SENSITIVE_ONCE
    assert session.bf_policy_refused_once is True
    assert session.bf_state == BF_S3
    
    # Second OTP request - should NOT refuse again with same intent
    action = choose_next_action(session, "i need the otp now", intel_dict, {}, settings)
    assert action["intent"] != INT_REFUSE_SENSITIVE_ONCE
    assert action["intent"] == INT_ASK_TICKET_REF # Default for S3 without no-progress
    
def test_intent_repetition_pivot(session, settings):
    intel_dict = asdict(session.extractedIntelligence)
    session.bf_state = BF_S1
    session.bf_last_intent = INT_ASK_OFFICIAL_HELPLINE
    session.bf_repeat_count = 1
    
    # Next action would normally be INT_ASK_OFFICIAL_HELPLINE again if no progress
    # But it should pivot after 2 repeats (repeat_count reaches 2)
    action = choose_next_action(session, "hello", intel_dict, {}, settings)
    # repeat_count will become 2 in this call
    assert session.bf_repeat_count == 0 # reset after pivot
    assert action["intent"] == INT_ASK_TICKET_REF # Pivot from HELPLINE
    assert action["reason"] == "repetition_pivot"

def test_secondary_bounce_limit(session, settings):
    intel_dict = asdict(session.extractedIntelligence)
    session.bf_state = BF_S3
    session.bf_last_ioc_signature = compute_ioc_signature(intel_dict)
    session.bf_no_progress_count = 1 # Will become 2 during choose_next_action
    session.bf_secondary_bounce_count = 0

    # Should bounce to S4
    action = choose_next_action(session, "no progress", intel_dict, {}, settings)
    assert session.bf_state == BF_S4
    assert session.bf_secondary_bounce_count == 1
    assert action["intent"] == INT_SECONDARY_FAIL

    # Now in S4, next turn should go back to S3
    action = choose_next_action(session, "still no progress", intel_dict, {}, settings)
    assert session.bf_state == BF_S3
    assert action["intent"] == INT_ASK_DEPARTMENT_BRANCH

    # Now in S3 again, with no progress, should go to S5 because bounce limit reached
    session.bf_no_progress_count = 1 # Will become 2
    action = choose_next_action(session, "really no progress", intel_dict, {}, settings)
    assert session.bf_state == BF_S5
    assert action["intent"] == INT_CLOSE_AND_VERIFY_SELF

def test_no_progress_pivot(session, settings):
    intel_dict = asdict(session.extractedIntelligence)
    session.bf_state = BF_S2
    session.bf_last_ioc_signature = compute_ioc_signature(intel_dict)
    session.bf_no_progress_count = 1
    
    # Another turn with same intel
    action = choose_next_action(session, "blah", intel_dict, {}, settings)
    assert session.bf_no_progress_count == 2
    assert session.bf_state == BF_S3
    assert action["intent"] == INT_ASK_ALT_VERIFICATION

def test_safety_filter(session):
    assert _safety_filter("please open sms and tell me the code") is True
    assert _safety_filter("go to your sms inbox") is True
    assert _safety_filter("copy the otp and paste it") is True
    assert _safety_filter("i am fine, how are you?") is False

def test_finalize_on_iocs(session, settings):
    session.scamDetected = True
    session.extractedIntelligence.phoneNumbers = ["1234567890"]
    session.extractedIntelligence.phishingLinks = ["http://scam.com"]
    
    # 2 categories = phone + link
    assert should_finalize(session) is True

def test_finalize_on_max_turns(session, settings):
    session.totalMessagesExchanged = settings.BF_MAX_TURNS * 2
    assert should_finalize(session) is True
